import math
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from flask import current_app, flash, jsonify, make_response, redirect, render_template, request, session, url_for
from flask_login import current_user

from user_models import get_user_by_id, get_user_by_username, get_username_by_id


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


def _parse_validity(validity):
    default_validity = current_app.config.get("PRESHARED_KEY_DEFAULT_VALIDITY", "60d")
    validity = (validity or default_validity).strip()
    try:
        seconds = parse_duration_generic(validity)
    except Exception:
        validity = default_validity
        seconds = parse_duration_generic(default_validity)
    return validity, seconds


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


def _api_psk_response(secret_value, row):
    response = make_response(secret_value)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{row["name"]}.psk.txt"'
    response.headers["X-PSK-Id"] = str(row["id"])
    response.headers["X-PSK-Name"] = row["name"]
    response.headers["X-PSK-Length"] = str(len(secret_value or ""))
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
    now = datetime.now(timezone.utc)
    expired = expires_dt is not None and expires_dt < now
    revoked = bool(row["revoked"])
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
        "validity": row["validity"] or "",
        "purpose": row["purpose"] or "",
        "note": row["note"] or "",
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
        SELECT id, name, secret_value, user_id, created_at, expires_at, last_used_at, revoked, validity, purpose, note
        FROM preshared_keys
    """
    params = []
    if owner_id is not None:
        query += " WHERE user_id = ?"
        params.append(owner_id)
    query += " ORDER BY created_at DESC, id DESC"
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
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


def _create_preshared_key(user_id, name, purpose, note, validity, length_chars):
    validity, seconds = _parse_validity(validity)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=seconds) if seconds else None
    secret_value = _build_secret(length_chars)
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        existing = conn.execute(
            "SELECT id FROM preshared_keys WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()
        if existing:
            raise ValueError(f"A pre-shared key named '{name}' already exists for this user.")
        conn.execute(
            """
            INSERT INTO preshared_keys (name, secret_value, user_id, created_at, expires_at, revoked, validity, purpose, note)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
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
            "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
        },
    )
    return {
        "id": psk_id,
        "name": name,
        "secret_value": secret_value,
        "user_id": user_id,
        "purpose": purpose or "",
        "note": note or "",
        "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else None,
        "validity": validity,
    }


def _lookup_preshared_key_for_token(key_name, verify_api_token):
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
        SELECT id, name, secret_value, user_id, created_at, expires_at, last_used_at, revoked, validity, purpose, note
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
    if row["revoked"]:
        return None, (jsonify({"error": "Pre-shared key is revoked"}), 410)
    if expires_dt is not None and expires_dt < now:
        return None, (jsonify({"error": "Pre-shared key is expired"}), 410)

    return dict(row), token_info


def preshared_keys():
    generated = session.pop("generated_preshared_key", None)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        purpose = request.form.get("purpose", "").strip()
        note = request.form.get("note", "").strip()
        validity = request.form.get("validity", "").strip()
        length_chars = request.form.get("length", "").strip()

        if not name:
            name = f"psk-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        try:
            created = _create_preshared_key(current_user.id, name, purpose, note, validity, length_chars)
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
            "UPDATE preshared_keys SET revoked = 1 WHERE id = ?",
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
    length_chars = payload.get("length") or request.form.get("length") or current_app.config.get("PRESHARED_KEY_LENGTH", 48)

    if not name:
        name = f"psk-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    try:
        created = _create_preshared_key(token_info["user_id"], name, purpose, note, validity, length_chars)
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
                "validity": created["validity"],
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

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute(
            "UPDATE preshared_keys SET last_used_at = ? WHERE id = ?",
            (now_str, row["id"]),
        )
        conn.commit()

    _log_event(
        "read",
        row["name"],
        token_info_or_response["user_id"],
        {"psk_id": row["id"], "via": "api_token"},
    )
    return _api_psk_response(row["secret_value"], row)
