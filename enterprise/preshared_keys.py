import math
import secrets
import sqlite3
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from flask import current_app, flash, jsonify, make_response, redirect, render_template, request, session, url_for
from flask_login import current_user

from user_models import get_user_by_id, get_user_by_username, get_username_by_id


PSK_PROFILE_CUSTOM = "custom"
PSK_PROFILE_AES_128 = "aes_128"
PSK_PROFILE_AES_192 = "aes_192"
PSK_PROFILE_AES_256 = "aes_256"
PSK_PROFILE_NIST_HIGH_256 = "nist_high_256"

PSK_PROFILE_DEFS = {
    PSK_PROFILE_CUSTOM: {"label": "Custom", "fixed_bytes": None, "default_length": None},
    PSK_PROFILE_AES_128: {"label": "AES-128", "fixed_bytes": 16, "default_length": 32},
    PSK_PROFILE_AES_192: {"label": "AES-192", "fixed_bytes": 24, "default_length": 48},
    PSK_PROFILE_AES_256: {"label": "AES-256", "fixed_bytes": 32, "default_length": 64},
    PSK_PROFILE_NIST_HIGH_256: {"label": "NIST Profile (High, 256-bit)", "fixed_bytes": 32, "default_length": 64},
}


def _normalize_psk_profile(psk_profile):
    normalized = (str(psk_profile or PSK_PROFILE_CUSTOM)).strip().lower()
    if normalized not in PSK_PROFILE_DEFS:
        return PSK_PROFILE_CUSTOM
    return normalized


def _psk_profile_label(psk_profile):
    normalized = _normalize_psk_profile(psk_profile)
    return PSK_PROFILE_DEFS.get(normalized, PSK_PROFILE_DEFS[PSK_PROFILE_CUSTOM])["label"]


def _available_psk_profiles():
    return [
        {"value": key, "label": meta["label"], "default_length": meta["default_length"]}
        for key, meta in PSK_PROFILE_DEFS.items()
    ]


def _ensure_preshared_key_schema(conn):
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(preshared_keys)")
    cols = [row[1] for row in cur.fetchall()]
    if "psk_profile" not in cols:
        cur.execute("ALTER TABLE preshared_keys ADD COLUMN psk_profile TEXT DEFAULT 'custom'")
    cur.execute("UPDATE preshared_keys SET psk_profile = 'custom' WHERE psk_profile IS NULL OR TRIM(psk_profile) = ''")


def parse_duration_generic(s):
    if not s:
        raise ValueError("Empty duration")
    import re

    s = s.strip().lower()
    match = re.match(r"^(\d+)([hdmy])$", s)
    if not match:
        raise ValueError(f"Invalid duration format: {s}")
    value, unit = match.groups()
    value = int(value)
    if unit == "h":
        return value * 3600
    if unit == "d":
        return value * 86400
    if unit == "m":
        return value * 86400 * 30
    if unit == "y":
        return value * 86400 * 365
    raise ValueError(f"Unknown duration unit: {unit}")


def _normalize_length(length_chars):
    try:
        length_chars = int(length_chars)
    except Exception:
        length_chars = current_app.config.get("PRESHARED_KEY_LENGTH", 48)
    return max(4, min(length_chars, 256))


def _token_bytes_for_length(length_chars):
    return math.ceil(length_chars * 3 / 4)


def _build_secret(length_chars):
    length_chars = _normalize_length(length_chars)
    return secrets.token_urlsafe(_token_bytes_for_length(length_chars))[:length_chars]


def _build_secret_for_profile(length_chars, psk_profile):
    normalized_profile = _normalize_psk_profile(psk_profile)
    fixed_bytes = PSK_PROFILE_DEFS[normalized_profile]["fixed_bytes"]
    if fixed_bytes is None:
        return _build_secret(length_chars)
    # For algorithm profiles, generate exact entropy and encode as hex.
    return secrets.token_hex(int(fixed_bytes))


def _parse_validity(validity):
    default_validity = current_app.config.get("PRESHARED_KEY_DEFAULT_VALIDITY", "60d")
    validity = (validity or default_validity).strip()
    try:
        seconds = parse_duration_generic(validity)
    except Exception:
        validity = default_validity
        seconds = parse_duration_generic(default_validity)
    return validity, seconds


def _parse_rotation_interval(interval):
    default_interval = current_app.config.get("PRESHARED_KEY_DEFAULT_ROTATION_INTERVAL", "2m")
    interval = (interval or default_interval).strip().lower()

    match = re.match(r"^(\d+)([smhd])$", interval)
    if not match:
        interval = default_interval
        match = re.match(r"^(\d+)([smhd])$", interval)
    value, unit = match.groups()
    value = int(value)
    if unit == "s":
        seconds = value
    elif unit == "m":
        seconds = value * 60
    elif unit == "h":
        seconds = value * 3600
    else:
        seconds = value * 86400
    return interval, seconds


def _format_rotation_remaining(next_rotation_dt, rotation_interval):
    if not next_rotation_dt or not rotation_interval:
        return ""
    match = re.match(r"^(\d+)([smhd])$", rotation_interval.strip().lower())
    if not match:
        return ""
    unit = match.group(2)
    unit_seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    remaining_seconds = max(0, int(math.ceil((next_rotation_dt - datetime.now(timezone.utc)).total_seconds())))
    remaining_units = max(0, int(math.ceil(remaining_seconds / unit_seconds)))
    return f"{remaining_units}{unit}"


def _rotation_remaining_seconds(next_rotation_dt):
    if not next_rotation_dt:
        return None
    return max(0, int(math.ceil((next_rotation_dt - datetime.now(timezone.utc)).total_seconds())))


def _extract_api_token():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    if request.headers.get("X-API-Token"):
        return request.headers.get("X-API-Token").strip()
    if request.args.get("token"):
        return request.args.get("token").strip()
    if request.is_json and isinstance(request.json, dict) and request.json.get("token"):
        return str(request.json.get("token")).strip()
    return None


PSK_OUTPUT_FORMATS = ("raw", "hex", "base64")


def _encode_psk_value(secret_value, output_format):
    secret_value = secret_value or ""
    if output_format == "hex":
        return secret_value.encode("utf-8").hex()
    if output_format == "base64":
        import base64

        return base64.b64encode(secret_value.encode("utf-8")).decode("ascii")
    return secret_value


def _api_psk_response(secret_value, row, output_format="raw"):
    body = _encode_psk_value(secret_value, output_format)
    response = make_response(body)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{row["name"]}.psk.txt"'
    response.headers["X-PSK-Id"] = str(row["id"])
    response.headers["X-PSK-Name"] = row["name"]
    response.headers["X-PSK-Length"] = str(len(secret_value or ""))
    response.headers["X-PSK-Encoding"] = output_format
    response.headers["X-PSK-Profile"] = _normalize_psk_profile(row.get("psk_profile"))
    rotation_mode = (row.get("rotation_mode") or "static").strip().lower()
    next_rotation_dt = _parse_dt(row.get("next_rotation_at"))
    rotation_remaining_seconds = -1 if rotation_mode != "rotating" else (_rotation_remaining_seconds(next_rotation_dt) or 0)
    response.headers["X-PSK-Rotation-Remaining-Seconds"] = str(rotation_remaining_seconds)
    if row.get("purpose"):
        response.headers["X-PSK-Purpose"] = row["purpose"]
    if row.get("expires_at"):
        response.headers["X-PSK-Expires-At"] = row["expires_at"]
    return response


def _parse_dt(dt_str):
    if not dt_str:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def _decorate_key_row(row):
    created_dt = _parse_dt(row["created_at"])
    expires_dt = _parse_dt(row["expires_at"])
    last_used_dt = _parse_dt(row["last_used_at"])
    last_rotated_dt = _parse_dt(row["last_rotated_at"])
    next_rotation_dt = _parse_dt(row["next_rotation_at"])
    now = datetime.now(timezone.utc)
    expired = expires_dt is not None and expires_dt < now
    revoked = bool(row["revoked"])
    rotation_mode = (row["rotation_mode"] or "static").strip().lower()
    psk_profile = _normalize_psk_profile(row["psk_profile"] if "psk_profile" in row.keys() else PSK_PROFILE_CUSTOM)
    is_rotating = rotation_mode == "rotating"
    if revoked:
        status = "Revoked"
        status_class = "badge badge-danger"
    elif expired:
        status = "Expired"
        status_class = "badge badge-secondary"
    else:
        status = "Active"
        status_class = "badge badge-success"
    return {
        "id": row["id"],
        "name": row["name"],
        "secret_value": row["secret_value"] or "",
        "secret_value_short": _short_secret(row["secret_value"] or ""),
        "length": len(row["secret_value"] or ""),
        "psk_profile": psk_profile,
        "psk_profile_label": _psk_profile_label(psk_profile),
        "validity": row["validity"] or "",
        "purpose": row["purpose"] or "",
        "note": row["note"] or "",
        "rotation_mode": "rotating" if is_rotating else "static",
        "rotation_label": "Rotating" if is_rotating else "Static",
        "rotation_interval": row["rotation_interval"] or "",
        "rotation_interval_configured": row["rotation_interval"] or "",
        "last_rotated_at": row["last_rotated_at"] or "",
        "last_rotated_at_local": last_rotated_dt.astimezone().strftime("%Y-%m-%d %H:%M") if last_rotated_dt else "",
        "rotation_started": bool(last_rotated_dt),
        "next_rotation_at": row["next_rotation_at"] or "",
        "next_rotation_at_local": next_rotation_dt.astimezone().strftime("%Y-%m-%d %H:%M") if next_rotation_dt else "",
        "rotation_remaining": _format_rotation_remaining(next_rotation_dt, row["rotation_interval"] or ""),
        "rotation_remaining_seconds": _rotation_remaining_seconds(next_rotation_dt),
        "user_id": row["user_id"],
        "user": get_username_by_id(row["user_id"]) if row["user_id"] else "",
        "created_at": row["created_at"] or "",
        "created_at_local": created_dt.astimezone().strftime("%Y-%m-%d %H:%M") if created_dt else "",
        "expires_at": row["expires_at"] or "",
        "expires_at_local": expires_dt.astimezone().strftime("%Y-%m-%d %H:%M") if expires_dt else "",
        "last_used_at": row["last_used_at"] or "",
        "last_used_at_local": last_used_dt.astimezone().strftime("%Y-%m-%d %H:%M") if last_used_dt else "",
        "revoked": revoked,
        "expired": expired,
        "status": status,
        "status_class": status_class,
    }


def _short_secret(value):
    preview_len = 32
    if len(value) <= preview_len:
        return value
    return f"{value[:preview_len]}..."


def _list_preshared_keys(owner_id=None):
    query = """
        SELECT id, name, secret_value, user_id, created_at, expires_at, last_used_at, revoked, validity, purpose, note,
               psk_profile,
               rotation_mode, rotation_interval, last_rotated_at, next_rotation_at
        FROM preshared_keys
    """
    params = []
    if owner_id is not None:
        query += " WHERE user_id = ?"
        params.append(owner_id)
    query += " ORDER BY created_at DESC, id DESC"
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        _ensure_preshared_key_schema(conn)
        _rotate_due_keys(conn, owner_id=owner_id)
        rows = conn.execute(query, params).fetchall()
    return [_decorate_key_row(row) for row in rows]


def _log_event(event_type, resource_name, user_id, details=None):
    try:
        from events import log_event

        log_event(
            event_type=event_type,
            resource_type="preshared_key",
            resource_name=resource_name,
            user_id=user_id,
            details=details or {},
        )
    except Exception:
        pass


def _create_preshared_key(user_id, name, purpose, note, validity, length_chars, rotation_interval, psk_profile):
    validity, seconds = _parse_validity(validity)
    rotation_interval, _rotation_seconds = _parse_rotation_interval(rotation_interval)
    psk_profile = _normalize_psk_profile(psk_profile)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=seconds) if seconds else None
    secret_value = _build_secret_for_profile(length_chars, psk_profile)
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        _ensure_preshared_key_schema(conn)
        existing = conn.execute(
            "SELECT id FROM preshared_keys WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()
        if existing:
            raise ValueError(f"A pre-shared key named '{name}' already exists for this user.")
        conn.execute(
            """
            INSERT INTO preshared_keys (
                name, secret_value, user_id, created_at, expires_at, revoked, validity, purpose, note,
                psk_profile,
                rotation_mode, rotation_interval, last_rotated_at, next_rotation_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, 'static', ?, NULL, NULL)
            """,
            (
                name,
                secret_value,
                user_id,
                now.strftime("%Y-%m-%d %H:%M:%S"),
                expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
                validity,
                purpose or None,
                note or None,
                psk_profile,
                rotation_interval,
            ),
        )
        psk_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    _log_event(
        "create",
        name,
        user_id,
        {
            "psk_id": psk_id,
            "purpose": purpose or "",
            "psk_profile": psk_profile,
            "psk_profile_label": _psk_profile_label(psk_profile),
            "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
            "rotation_mode": "static",
            "rotation_interval": rotation_interval,
        },
    )
    return {
        "id": psk_id,
        "name": name,
        "secret_value": secret_value,
        "user_id": user_id,
        "purpose": purpose or "",
        "note": note or "",
        "psk_profile": psk_profile,
        "psk_profile_label": _psk_profile_label(psk_profile),
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
        "validity": validity,
        "rotation_mode": "static",
        "rotation_interval": rotation_interval,
    }


def _rotate_row(conn, row, user_id, start_rotating=False):
    row_id = row["id"]
    row_name = row["name"]
    length_chars = len(row["secret_value"] or "")
    secret_value = _build_secret(length_chars)
    now = datetime.now(timezone.utc)
    interval = row["rotation_interval"] or ""
    update_sql = """
        UPDATE preshared_keys
        SET secret_value = ?, last_rotated_at = ?, next_rotation_at = ?, rotation_mode = ?
        WHERE id = ?
    """
    next_rotation_at = None
    new_mode = (row["rotation_mode"] or "static").strip().lower()
    if start_rotating:
        new_mode = "rotating"
    if new_mode == "rotating" and interval:
        _, rotation_seconds = _parse_rotation_interval(interval)
        next_rotation_at = now + timedelta(seconds=rotation_seconds)
    elif new_mode != "rotating":
        next_rotation_at = None
    conn.execute(
        update_sql,
        (
            secret_value,
            now.strftime("%Y-%m-%d %H:%M:%S"),
            next_rotation_at.strftime("%Y-%m-%d %H:%M:%S") if next_rotation_at else None,
            new_mode,
            row_id,
        ),
    )
    return {
        "secret_value": secret_value,
        "psk_id": row_id,
        "name": row_name,
        "user_id": user_id,
        "rotation_mode": new_mode,
        "rotation_interval": interval,
        "next_rotation_at": next_rotation_at.strftime("%Y-%m-%d %H:%M:%S") if next_rotation_at else None,
    }


def _rotate_due_keys(conn, owner_id=None):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    query = """
        SELECT id, name, secret_value, user_id, rotation_mode, rotation_interval, next_rotation_at, revoked, expires_at
        FROM preshared_keys
        WHERE rotation_mode = 'rotating'
          AND rotation_interval IS NOT NULL
          AND rotation_interval != ''
          AND revoked = 0
          AND (expires_at IS NULL OR expires_at > ?)
          AND next_rotation_at IS NOT NULL
          AND next_rotation_at <= ?
    """
    params = [now_str, now_str]
    if owner_id is not None:
        query += " AND user_id = ?"
        params.append(owner_id)
    conn.row_factory = sqlite3.Row
    due_rows = conn.execute(query, params).fetchall()
    for row in due_rows:
        _rotate_row(conn, row, row["user_id"], start_rotating=False)
    if due_rows:
        conn.commit()


def _fetch_psk_row_for_owner(conn, psk_id):
    conn.row_factory = sqlite3.Row
    return conn.execute(
        """
     SELECT id, name, secret_value, user_id, created_at, expires_at, last_used_at, revoked, validity, purpose, note,
         psk_profile,
               rotation_mode, rotation_interval, last_rotated_at, next_rotation_at
        FROM preshared_keys
        WHERE id = ?
        """,
        (psk_id,),
    ).fetchone()


def _lookup_preshared_key_for_token(key_name, verify_api_token, allow_inactive=False):
    raw_token = _extract_api_token()
    if not raw_token:
        return None, (jsonify({"error": "API token required"}), 401)

    token_info = verify_api_token(raw_token)
    if not token_info:
        return None, (jsonify({"error": "Invalid or expired API token"}), 401)

    token_user = get_user_by_id(token_info["user_id"])
    if token_user is None:
        return None, (jsonify({"error": "Token owner not found"}), 404)

    normalized_name = (unquote(key_name or "")).strip()
    if not normalized_name:
        return None, (jsonify({"error": "Pre-shared key name is required"}), 400)

    query = """
         SELECT id, name, secret_value, user_id, created_at, expires_at, last_used_at, revoked, validity, purpose, note,
             psk_profile,
               rotation_mode, rotation_interval, last_rotated_at, next_rotation_at
        FROM preshared_keys
        WHERE name = ?
    """
    params = [normalized_name]
    if not token_user.is_admin():
        query += " AND user_id = ?"
        params.append(token_info["user_id"])
    else:
        owner_user_id = request.args.get("user_id", type=int)
        owner_username = (request.args.get("username") or "").strip()
        if owner_user_id is not None:
            query += " AND user_id = ?"
            params.append(owner_user_id)
        elif owner_username:
            owner = get_user_by_username(owner_username)
            if owner is None:
                return None, (jsonify({"error": f"Username '{owner_username}' not found"}), 404)
            query += " AND user_id = ?"
            params.append(owner.id)

    query += " ORDER BY created_at DESC, id DESC"
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        _ensure_preshared_key_schema(conn)
        _rotate_due_keys(conn, owner_id=None if token_user.is_admin() else token_info["user_id"])
        rows = conn.execute(query, params).fetchall()

    if not rows:
        return None, (jsonify({"error": f"Pre-shared key '{normalized_name}' not found"}), 404)
    if token_user.is_admin() and len(rows) > 1:
        return None, (
            jsonify({"error": "Multiple PSKs share this name; supply ?user_id= or ?username= to disambiguate"}),
            409,
        )

    row = rows[0]
    expires_dt = _parse_dt(row["expires_at"])
    now = datetime.now(timezone.utc)
    if not allow_inactive and row["revoked"]:
        return None, (jsonify({"error": "Pre-shared key is revoked"}), 410)
    if not allow_inactive and expires_dt is not None and expires_dt < now:
        return None, (jsonify({"error": "Pre-shared key is expired"}), 410)

    return dict(row), token_info


def _api_rotation_response(row, value=None):
    payload = {
        "id": row["id"],
        "name": row["name"],
        "user_id": row["user_id"],
        "psk_profile": _normalize_psk_profile(row.get("psk_profile")),
        "psk_profile_label": _psk_profile_label(row.get("psk_profile")),
        "rotation_mode": row.get("rotation_mode") or "static",
        "rotation_interval": row.get("rotation_interval") or "",
        "last_rotated_at": row.get("last_rotated_at"),
        "next_rotation_at": row.get("next_rotation_at"),
        "expires_at": row.get("expires_at"),
    }
    if value is not None:
        payload["value"] = value
    return jsonify(payload)


def preshared_keys():
    generated = session.pop("generated_preshared_key", None)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        purpose = request.form.get("purpose", "").strip()
        note = request.form.get("note", "").strip()
        validity = request.form.get("validity", "").strip()
        rotation_interval = request.form.get("rotation_interval", "").strip()
        length_chars = request.form.get("length", "").strip()
        psk_profile = _normalize_psk_profile(request.form.get("psk_profile", PSK_PROFILE_CUSTOM))

        if not name:
            name = f"psk-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        try:
            created = _create_preshared_key(
                current_user.id,
                name,
                purpose,
                note,
                validity,
                length_chars,
                rotation_interval,
                psk_profile,
            )
            session["generated_preshared_key"] = created
            flash("Pre-shared key created. Copy it now; the UI will not reveal it again after this page load.", "success")
            return redirect(url_for("preshared_keys"))
        except ValueError as exc:
            flash(str(exc), "error")
        except Exception as exc:
            current_app.logger.error(f"[preshared_keys] Failed to create PSK: {exc}")
            flash("Failed to create pre-shared key. Please try again.", "error")

    keys = _list_preshared_keys() if current_user.is_admin() else _list_preshared_keys(current_user.id)
    return render_template(
        "preshared_keys.html",
        preshared_keys=keys,
        generated=generated,
        is_admin=current_user.is_admin(),
        default_validity=current_app.config.get("PRESHARED_KEY_DEFAULT_VALIDITY", "60d"),
        default_length=current_app.config.get("PRESHARED_KEY_LENGTH", 48),
        default_rotation_interval=current_app.config.get("PRESHARED_KEY_DEFAULT_ROTATION_INTERVAL", "2m"),
        psk_profiles=_available_psk_profiles(),
        default_psk_profile=PSK_PROFILE_CUSTOM,
    )


def preshared_keys_state():
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        if current_user.is_admin():
            row = conn.execute("SELECT COUNT(*) as cnt, IFNULL(MAX(id),0) as max_id FROM preshared_keys").fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) as cnt, IFNULL(MAX(id),0) as max_id FROM preshared_keys WHERE user_id = ?",
                (current_user.id,),
            ).fetchone()
    return jsonify({"count": row[0], "max_id": row[1]})


def preshared_keys_data():
    keys = _list_preshared_keys() if current_user.is_admin() else _list_preshared_keys(current_user.id)
    return jsonify(keys)


def revoke_preshared_key(psk_id):
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, user_id, revoked FROM preshared_keys WHERE id = ?",
            (psk_id,),
        ).fetchone()
        if not row:
            flash("Pre-shared key not found.", "error")
            return redirect(url_for("preshared_keys"))
        if row["user_id"] != current_user.id and not current_user.is_admin():
            flash("You do not have permission to revoke this pre-shared key.", "error")
            return redirect(url_for("preshared_keys"))
        if row["revoked"]:
            flash("Pre-shared key is already revoked.", "info")
            return redirect(url_for("preshared_keys"))
        conn.execute(
            "UPDATE preshared_keys SET revoked = 1, rotation_mode = 'static', next_rotation_at = NULL WHERE id = ?",
            (psk_id,),
        )
        conn.commit()
    _log_event("revoke", row["name"], current_user.id, {"psk_id": psk_id})
    flash(f"Pre-shared key '{row['name']}' revoked.", "success")
    return redirect(url_for("preshared_keys"))


def delete_preshared_key(psk_id):
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, user_id FROM preshared_keys WHERE id = ?",
            (psk_id,),
        ).fetchone()
        if not row:
            flash("Pre-shared key not found.", "error")
            return redirect(url_for("preshared_keys"))
        if row["user_id"] != current_user.id and not current_user.is_admin():
            flash("You do not have permission to delete this pre-shared key.", "error")
            return redirect(url_for("preshared_keys"))
        conn.execute("DELETE FROM preshared_keys WHERE id = ?", (psk_id,))
        conn.commit()
    _log_event("delete", row["name"], current_user.id, {"psk_id": psk_id})
    flash(f"Pre-shared key '{row['name']}' deleted.", "success")
    return redirect(url_for("preshared_keys"))


def regenerate_preshared_key(psk_id):
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        row = _fetch_psk_row_for_owner(conn, psk_id)
        if not row:
            flash("Pre-shared key not found.", "error")
            return redirect(url_for("preshared_keys"))
        if row["user_id"] != current_user.id and not current_user.is_admin():
            flash("You do not have permission to regenerate this pre-shared key.", "error")
            return redirect(url_for("preshared_keys"))
        if row["revoked"]:
            flash("Revoked pre-shared keys cannot be regenerated.", "error")
            return redirect(url_for("preshared_keys"))
        rotation_event = _rotate_row(conn, row, current_user.id, start_rotating=True)
        conn.commit()
    _log_event(
        "rotating_mode",
        rotation_event["name"],
        current_user.id,
        {
            "psk_id": rotation_event["psk_id"],
            "rotation_mode": rotation_event["rotation_mode"],
            "rotation_interval": rotation_event["rotation_interval"],
            "next_rotation_at": rotation_event["next_rotation_at"],
        },
    )
    flash(f"Pre-shared key '{row['name']}' rotated and set to rotating mode.", "success")
    return redirect(url_for("preshared_keys"))


def toggle_preshared_key_rotation(psk_id):
    db_path = current_app.config["DB_PATH"]
    with sqlite3.connect(db_path) as conn:
        row = _fetch_psk_row_for_owner(conn, psk_id)
        if not row:
            flash("Pre-shared key not found.", "error")
            return redirect(url_for("preshared_keys"))
        if row["user_id"] != current_user.id and not current_user.is_admin():
            flash("You do not have permission to change this pre-shared key.", "error")
            return redirect(url_for("preshared_keys"))
        if row["revoked"]:
            flash("Revoked pre-shared keys cannot change rotation mode.", "error")
            return redirect(url_for("preshared_keys"))
        current_mode = (row["rotation_mode"] or "static").strip().lower()
        if current_mode == "rotating":
            conn.execute(
                "UPDATE preshared_keys SET rotation_mode = 'static', next_rotation_at = NULL WHERE id = ?",
                (psk_id,),
            )
            conn.commit()
            _log_event("stop_rotating_mode", row["name"], current_user.id, {"psk_id": psk_id, "rotation_mode": "static"})
            flash(f"Pre-shared key '{row['name']}' stopped rotating.", "success")
        else:
            interval = row["rotation_interval"] or ""
            if not interval:
                flash("This pre-shared key has no rotation interval configured.", "error")
                return redirect(url_for("preshared_keys"))
            if not row["last_rotated_at"]:
                flash("Use Rotate first to create a new value and start rotation for this pre-shared key.", "info")
                return redirect(url_for("preshared_keys"))
            _, rotation_seconds = _parse_rotation_interval(interval)
            next_rotation_at = datetime.now(timezone.utc) + timedelta(seconds=rotation_seconds)
            conn.execute(
                "UPDATE preshared_keys SET rotation_mode = 'rotating', next_rotation_at = ? WHERE id = ?",
                (next_rotation_at.strftime("%Y-%m-%d %H:%M:%S"), psk_id),
            )
            conn.commit()
            _log_event(
                "rotating_mode",
                row["name"],
                current_user.id,
                {
                    "psk_id": psk_id,
                    "rotation_mode": "rotating",
                    "next_rotation_at": next_rotation_at.strftime("%Y-%m-%d %H:%M:%S"),
                },
            )
            flash(f"Pre-shared key '{row['name']}' set to rotating mode.", "success")
    return redirect(url_for("preshared_keys"))


def api_create_preshared_key(verify_api_token):
    raw_token = _extract_api_token()
    if not raw_token:
        return jsonify({"error": "API token required"}), 401

    token_info = verify_api_token(raw_token)
    if not token_info:
        return jsonify({"error": "Invalid or expired API token"}), 401

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or request.form.get("name") or "").strip()
    purpose = str(payload.get("purpose") or request.form.get("purpose") or "").strip()
    note = str(payload.get("note") or request.form.get("note") or "").strip()
    validity = str(payload.get("validity") or request.form.get("validity") or "").strip()
    rotation_interval = str(payload.get("rotation_interval") or request.form.get("rotation_interval") or "").strip()
    length_chars = payload.get("length") or request.form.get("length") or current_app.config.get("PRESHARED_KEY_LENGTH", 48)
    psk_profile = _normalize_psk_profile(
        payload.get("psk_profile") or request.form.get("psk_profile") or PSK_PROFILE_CUSTOM
    )

    if not name:
        name = f"psk-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    try:
        created = _create_preshared_key(
            token_info["user_id"],
            name,
            purpose,
            note,
            validity,
            length_chars,
            rotation_interval,
            psk_profile,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409
    except Exception as exc:
        current_app.logger.error(f"[preshared_keys] API create failed: {exc}")
        return jsonify({"error": "Failed to create pre-shared key"}), 500

    return (
        jsonify(
            {
                "id": created["id"],
                "name": created["name"],
                "value": created["secret_value"],
                "user_id": created["user_id"],
                "purpose": created["purpose"],
                "note": created["note"],
                "psk_profile": created["psk_profile"],
                "psk_profile_label": created["psk_profile_label"],
                "validity": created["validity"],
                "rotation_mode": created["rotation_mode"],
                "rotation_interval": created["rotation_interval"],
                "created_at": created["created_at"],
                "expires_at": created["expires_at"],
            }
        ),
        201,
    )


def api_get_preshared_key(key_name, verify_api_token):
    row, token_info_or_response = _lookup_preshared_key_for_token(key_name, verify_api_token)
    if row is None:
        return token_info_or_response

    output_format = (request.args.get("format") or request.args.get("encoding") or "raw").strip().lower()
    if output_format not in PSK_OUTPUT_FORMATS:
        return jsonify({"error": f"Unsupported format '{output_format}'. Use one of: {', '.join(PSK_OUTPUT_FORMATS)}"}), 400

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute(
            "UPDATE preshared_keys SET last_used_at = ? WHERE id = ?",
            (now_str, row["id"]),
        )
        conn.commit()
    return _api_psk_response(row["secret_value"], row, output_format)


def api_delete_preshared_key(key_name, verify_api_token):
    row, token_info_or_response = _lookup_preshared_key_for_token(key_name, verify_api_token, allow_inactive=True)
    if row is None:
        return token_info_or_response

    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute("DELETE FROM preshared_keys WHERE id = ?", (row["id"],))
        conn.commit()

    _log_event(
        "delete",
        row["name"],
        token_info_or_response["user_id"],
        {"psk_id": row["id"], "via": "api_token"},
    )
    return jsonify({"deleted": True, "id": row["id"], "name": row["name"], "user_id": row["user_id"]})


def api_start_preshared_key_rotation(key_name, verify_api_token):
    row, token_info_or_response = _lookup_preshared_key_for_token(key_name, verify_api_token)
    if row is None:
        return token_info_or_response

    if row["revoked"]:
        return jsonify({"error": "Pre-shared key is revoked"}), 410

    interval = row.get("rotation_interval") or ""
    if not interval:
        return jsonify({"error": "Pre-shared key has no rotation interval configured"}), 400

    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        rotation_event = _rotate_row(conn, row, token_info_or_response["user_id"], start_rotating=True)
        conn.commit()
        updated_row = _fetch_psk_row_for_owner(conn, row["id"])

    _log_event(
        "rotating_mode",
        rotation_event["name"],
        token_info_or_response["user_id"],
        {
            "psk_id": rotation_event["psk_id"],
            "rotation_mode": rotation_event["rotation_mode"],
            "rotation_interval": rotation_event["rotation_interval"],
            "next_rotation_at": rotation_event["next_rotation_at"],
            "via": "api_token",
        },
    )
    return _api_rotation_response(dict(updated_row), value=rotation_event["secret_value"])


def api_stop_preshared_key_rotation(key_name, verify_api_token):
    row, token_info_or_response = _lookup_preshared_key_for_token(key_name, verify_api_token)
    if row is None:
        return token_info_or_response

    if row["revoked"]:
        return jsonify({"error": "Pre-shared key is revoked"}), 410

    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute(
            "UPDATE preshared_keys SET rotation_mode = 'static', next_rotation_at = NULL WHERE id = ?",
            (row["id"],),
        )
        conn.commit()
        updated_row = _fetch_psk_row_for_owner(conn, row["id"])

    _log_event(
        "stop_rotating_mode",
        row["name"],
        token_info_or_response["user_id"],
        {"psk_id": row["id"], "rotation_mode": "static", "via": "api_token"},
    )
    return _api_rotation_response(dict(updated_row))
