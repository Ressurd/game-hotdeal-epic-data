#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


TARGET_DIRS = ("list-cache", "state", "detail")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Normalize expired discounts by restoring base prices."
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Root of the data repo (defaults to current directory).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing files.",
    )
    parser.add_argument(
        "--now",
        default="",
        help="Override current time (ISO-8601, e.g. 2026-01-31T00:00:00Z).",
    )
    return parser.parse_args()


def resolve_base(root: Path) -> Path:
    public_root = root / "public"
    if public_root.is_dir() and not (root / "list-cache").is_dir():
        if (public_root / "list-cache").is_dir():
            return public_root
    return root


def parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def sanitize_payload(value):
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, list):
        return [sanitize_payload(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_payload(item) for key, item in value.items()}
    return value


def save_json(path: Path, payload, dry_run: bool):
    if dry_run:
        return
    payload = sanitize_payload(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))


def normalize_price_fields(
    item: dict,
    now: datetime,
    price_key: str,
    base_key: str,
    percent_key: str,
    end_key: str,
) -> bool:
    discount_end = parse_iso(item.get(end_key))
    if not discount_end or discount_end >= now:
        return False
    discount_percent = item.get(percent_key) or 0
    if discount_percent <= 0:
        return False
    price = item.get(price_key)
    base = item.get(base_key)
    if isinstance(base, (int, float)):
        item[price_key] = base
        item[base_key] = base
    elif isinstance(price, (int, float)):
        item[base_key] = price
    item[percent_key] = 0
    item[end_key] = None
    return True


def normalize_list_cache(path: Path, now: datetime, dry_run: bool, stats: dict):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return
    changed = 0
    for item in payload:
        if not isinstance(item, dict):
            continue
        if normalize_price_fields(
            item, now, "price", "basePrice", "discountPercent", "discountEnd"
        ):
            changed += 1
    if changed == 0:
        return
    stats["list_cache_changed"] += changed
    stats["files_updated"] += 1
    save_json(path, payload, dry_run)


def normalize_state(path: Path, now: datetime, dry_run: bool, stats: dict):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return
    changed_items = 0
    for item in payload:
        if not isinstance(item, dict):
            continue
        changed = normalize_price_fields(
            item,
            now,
            "latestPrice",
            "latestBasePrice",
            "latestDiscountPercent",
            "latestDiscountEnd",
        )
        changed_usd = normalize_price_fields(
            item,
            now,
            "latestPriceUsd",
            "latestBasePriceUsd",
            "latestDiscountPercentUsd",
            "latestDiscountEndUsd",
        )
        if changed or changed_usd:
            item["discountStartAt"] = None
            changed_items += 1
    if changed_items == 0:
        return
    stats["state_changed"] += changed_items
    stats["files_updated"] += 1
    save_json(path, payload, dry_run)


def normalize_detail(path: Path, now: datetime, dry_run: bool, stats: dict):
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return
    changed = 0
    latest = payload.get("latest")
    if isinstance(latest, dict):
        if normalize_price_fields(
            latest, now, "price", "basePrice", "discountPercent", "discountEnd"
        ):
            changed += 1
        payload["latest"] = latest
    dlc_list = payload.get("dlcList")
    if isinstance(dlc_list, list):
        dlc_changed = 0
        for item in dlc_list:
            if not isinstance(item, dict):
                continue
            if normalize_price_fields(
                item, now, "price", "basePrice", "discountPercent", "discountEnd"
            ):
                dlc_changed += 1
        if dlc_changed:
            payload["dlcList"] = dlc_list
            stats["detail_dlc_changed"] += dlc_changed
            changed += dlc_changed
    if changed == 0:
        return
    stats["detail_changed"] += 1
    stats["files_updated"] += 1
    save_json(path, payload, dry_run)


def main():
    args = parse_args()
    root = Path(args.root).resolve()
    base = resolve_base(root)
    missing_dirs = [name for name in TARGET_DIRS if not (base / name).exists()]
    if missing_dirs:
        print(f"Warning: missing directories under {base}: {', '.join(missing_dirs)}")

    now = parse_iso(args.now) if args.now else datetime.now(timezone.utc)
    stats = {
        "files_scanned": 0,
        "files_updated": 0,
        "list_cache_changed": 0,
        "state_changed": 0,
        "detail_changed": 0,
        "detail_dlc_changed": 0,
    }

    list_dir = base / "list-cache"
    if list_dir.is_dir():
        for path in list_dir.glob("*.json"):
            stats["files_scanned"] += 1
            normalize_list_cache(path, now, args.dry_run, stats)

    state_dir = base / "state"
    if state_dir.is_dir():
        for path in state_dir.glob("*.json"):
            stats["files_scanned"] += 1
            normalize_state(path, now, args.dry_run, stats)

    detail_dir = base / "detail"
    if detail_dir.is_dir():
        for path in detail_dir.rglob("*.json"):
            stats["files_scanned"] += 1
            normalize_detail(path, now, args.dry_run, stats)

    print(
        "Done.",
        f"Scanned={stats['files_scanned']}",
        f"Updated={stats['files_updated']}",
        f"ListCacheChanged={stats['list_cache_changed']}",
        f"StateChanged={stats['state_changed']}",
        f"DetailChanged={stats['detail_changed']}",
        f"DetailDlcChanged={stats['detail_dlc_changed']}",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
