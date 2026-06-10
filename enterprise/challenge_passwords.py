from datetime import datetime, timedelta, timezone
import re


CHALLENGE_MODE_SINGLE_USE = "single_use"
CHALLENGE_MODE_REUSABLE = "reusable"
CHALLENGE_MODE_REUSABLE_UNLIMITED = "reusable_unlimited"

CHALLENGE_MODE_CHOICES = (
    CHALLENGE_MODE_SINGLE_USE,
    CHALLENGE_MODE_REUSABLE,
    CHALLENGE_MODE_REUSABLE_UNLIMITED,
)

DEFAULT_CHALLENGE_MODE = CHALLENGE_MODE_SINGLE_USE


def normalize_challenge_mode(value):
    raw = (value or "").strip().lower()
    aliases = {
        "single": CHALLENGE_MODE_SINGLE_USE,
        "single_use": CHALLENGE_MODE_SINGLE_USE,
        "single-use": CHALLENGE_MODE_SINGLE_USE,
        "reusable": CHALLENGE_MODE_REUSABLE,
        "multi_use": CHALLENGE_MODE_REUSABLE,
        "multi-use": CHALLENGE_MODE_REUSABLE,
        "reusable_unlimited": CHALLENGE_MODE_REUSABLE_UNLIMITED,
        "reusable-unlimited": CHALLENGE_MODE_REUSABLE_UNLIMITED,
        "unlimited": CHALLENGE_MODE_REUSABLE_UNLIMITED,
        "unlimited_use": CHALLENGE_MODE_REUSABLE_UNLIMITED,
        "unlimited-use": CHALLENGE_MODE_REUSABLE_UNLIMITED,
    }
    return aliases.get(raw, DEFAULT_CHALLENGE_MODE)


def is_unlimited_mode(mode):
    return normalize_challenge_mode(mode) == CHALLENGE_MODE_REUSABLE_UNLIMITED


def parse_validity_timedelta(validity_str):
    m = re.match(r"^(\d+)([mhd])$", (validity_str or "").strip())
    if not m:
        return timedelta(minutes=60), "60m"
    num, unit = int(m.group(1)), m.group(2)
    if unit == "m":
        return timedelta(minutes=num), validity_str
    if unit == "h":
        return timedelta(hours=num), validity_str
    if unit == "d":
        return timedelta(days=num), validity_str
    return timedelta(minutes=60), "60m"


def parse_created_at(created_at):
    if not created_at:
        return None
    try:
        return datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def format_utc(dt_obj):
    if not dt_obj:
        return ""
    return dt_obj.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_local(dt_obj):
    if not dt_obj:
        return ""
    return dt_obj.astimezone().strftime("%Y-%m-%d %H:%M")


def compute_expiry(created_at, validity, usage_mode):
    if is_unlimited_mode(usage_mode):
        return None, False
    created_dt = parse_created_at(created_at)
    if not created_dt or not validity:
        return None, False
    delta, _ = parse_validity_timedelta(validity)
    expires_dt = created_dt + delta
    return expires_dt, datetime.now(timezone.utc) > expires_dt


def derive_use_count(row):
    use_count = int(row["use_count"] or 0)
    if use_count <= 0 and bool(row["consumed"]):
        return 1
    return use_count


def derive_status(usage_mode, use_count, expired):
    mode = normalize_challenge_mode(usage_mode)
    if expired:
        return "expired", "Expired", "badge badge-secondary"
    if mode == CHALLENGE_MODE_SINGLE_USE:
        if use_count > 0:
            return "consumed", "Consumed", "badge badge-danger"
        return "available", "Available", "badge badge-success"
    if mode == CHALLENGE_MODE_REUSABLE:
        if use_count > 0:
            return "used_reusable", "Used - Reusable", "badge badge-warning"
        return "available", "Available", "badge badge-success"
    if use_count > 0:
        return "used_unlimited", "Used - Unlimited", "badge badge-info"
    return "unlimited", "Unlimited", "badge badge-primary"


def can_delete_entry(usage_mode, use_count, expired):
    return True


def usage_mode_label(usage_mode):
    mode = normalize_challenge_mode(usage_mode)
    if mode == CHALLENGE_MODE_SINGLE_USE:
        return "Single Use"
    if mode == CHALLENGE_MODE_REUSABLE:
        return "Reusable"
    return "Reusable Unlimited"


def build_challenge_password_view(row, username=""):
    usage_mode = normalize_challenge_mode(row["usage_mode"])
    use_count = derive_use_count(row)
    expires_dt, expired = compute_expiry(row["created_at"], row["validity"], usage_mode)
    status_key, status_label, status_class = derive_status(usage_mode, use_count, expired)
    created_dt = parse_created_at(row["created_at"])
    last_used_dt = parse_created_at(row["last_used_at"])
    return {
        "value": row["value"],
        "user": username or "",
        "created_at_utc": row["created_at"],
        "created_at_local": format_local(created_dt),
        "validity": row["validity"] if row["validity"] else "Unlimited",
        "expires_at_utc": format_utc(expires_dt),
        "expires_at_local": format_local(expires_dt),
        "expired": expired,
        "consumed": status_key == "consumed",
        "allow_delete": can_delete_entry(usage_mode, use_count, expired),
        "usage_mode": usage_mode,
        "usage_mode_label": usage_mode_label(usage_mode),
        "use_count": use_count,
        "last_used_at_utc": format_utc(last_used_dt),
        "last_used_at_local": format_local(last_used_dt),
        "status_key": status_key,
        "status_label": status_label,
        "status_class": status_class,
    }
