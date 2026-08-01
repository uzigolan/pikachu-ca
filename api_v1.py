"""
api_v1.py – JSON REST API Blueprint at /api/v1/

All routes are authenticated via API token (Authorization: Bearer <token>
or X-API-Token header). Tokens inherit the role of the user who created
them: admin-role tokens unlock [ADMIN] endpoints.
"""

import os
import re
import json
import secrets
import sqlite3
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from flask import Blueprint, current_app, g, jsonify, request

from edition import feature_enabled
from events import log_event
from extensions import db
from openssl_utils import get_provider_args
from ra_policies import DEFAULT_VALIDITY_DAYS, RAPolicyManager
from user_models import get_all_users, get_user_by_id, create_user_db
from users import verify_api_token
from x509_keys import Key
from x509_profiles import Profile
from x509_requests import CSR

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _extract_raw_token():
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.headers.get("X-API-Token", "").strip() or None


def _require_token(admin_only=False):
    """Decorator: verify API token, set g.token_user / g.token_info."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not feature_enabled("api_tokens"):
                return jsonify({"error": "API tokens are not available in this edition"}), 404
            raw = _extract_raw_token()
            if not raw:
                return jsonify({"error": "API token required (Authorization: Bearer <token>)"}), 401
            token_info = verify_api_token(raw)
            if not token_info:
                return jsonify({"error": "Invalid or expired API token"}), 401
            user = get_user_by_id(token_info["user_id"])
            if not user or not user.is_active:
                return jsonify({"error": "Token owner not found or inactive"}), 401
            if admin_only and not user.is_admin():
                return jsonify({
                    "error": "[ADMIN] This operation requires an admin token. "
                             "Create your API token while logged in as an admin-role user."
                }), 403
            g.token_info = token_info
            g.token_user = user
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _mgr():
    """Return a RAPolicyManager bound to the current app DB."""
    return RAPolicyManager(current_app.config["DB_PATH"], current_app.logger)


# ---------------------------------------------------------------------------
# CSR / signing helpers (no import from app.py to avoid circular deps)
# ---------------------------------------------------------------------------

def _normalize_csr_pem(text: str) -> str:
    text = (text or "").strip()
    if not text:
        raise ValueError("CSR is empty")
    if "BEGIN CERTIFICATE REQUEST" not in text:
        raise ValueError("CSR must be PEM-encoded (BEGIN CERTIFICATE REQUEST)")
    return text.rstrip() + "\n"


def _sign_csr_pem(csr_pem: str, policy, validity_days: int, no_extensions: bool,
                   use_csr_extensions: bool, user_id: int, issued_via: str = "manual") -> dict:
    """
    Sign a CSR PEM using the sub-CA and return a dict with cert_pem and serial.
    Raises RuntimeError on failure.
    """
    csr_obj = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    subject_str = ", ".join(f"{a.oid._name}={a.value}" for a in csr_obj.subject)
    custom_serial_str = hex(secrets.randbits(64))

    if current_app.config.get("VAULT_ENABLED", False):
        raise NotImplementedError("Vault-backed signing is not yet supported in the JSON API. "
                                  "Use the web UI for Vault mode.")

    mgr = _mgr()

    @contextmanager
    def _temp_extfile(pol):
        if no_extensions or use_csr_extensions or not pol:
            yield None
            return
        yield from mgr.temp_extfile(pol)

    with _temp_extfile(policy) as extfile_path:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as f:
            f.write(csr_pem.encode())
            csr_file = f.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as f:
            cert_file = f.name
        try:
            cmd = ["openssl", "x509"]
            cmd.extend(get_provider_args())
            cmd.extend([
                "-req",
                "-in", csr_file,
                "-CA", current_app.config["SUBCA_CERT_PATH"],
                "-CAkey", current_app.config["SUBCA_KEY_PATH"],
                "-set_serial", custom_serial_str,
                "-CAcreateserial",
                "-days", str(validity_days),
                "-out", cert_file,
            ])
            if extfile_path:
                cmd.extend(["-extfile", extfile_path, "-extensions", "v3_ext"])
            if use_csr_extensions:
                cmd.extend(["-copy_extensions", "copy"])

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"OpenSSL signing failed: {result.stderr.strip()}")

            with open(cert_file) as f:
                cert_pem = f.read()
        finally:
            for p in (csr_file, cert_file):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    serial = hex(cert_obj.serial_number)
    common_name = ""
    attrs = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if attrs:
        common_name = attrs[0].value
    not_before = cert_obj.not_valid_before_utc.isoformat()
    not_after = cert_obj.not_valid_after_utc.isoformat()

    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        pub = cert_obj.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            keycol = f"RSA/{pub.key_size}"
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            keycol = f"EC/{pub.curve.name}"
        else:
            keycol = "Unknown"
    except Exception:
        keycol = "Unknown"

    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute(
            """INSERT INTO certificates
               (subject, serial, cert_pem, user_id, issued_via,
                common_name, keycol, not_valid_before, not_valid_after)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (subject_str, serial, cert_pem, user_id, issued_via,
             common_name, keycol, not_before, not_after),
        )
        cert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    log_event("create", "certificate", serial, user_id, {"subject": subject_str})

    return {
        "id": cert_id,
        "serial": serial,
        "subject": subject_str,
        "common_name": common_name,
        "not_valid_before": not_before,
        "not_valid_after": not_after,
        "keycol": keycol,
        "issued_via": issued_via,
        "cert_pem": cert_pem,
    }


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

# Allowed sort columns for certificates
_CERT_SORT_COLS = {
    "id": "c.id", "common_name": "c.common_name", "serial": "c.serial",
    "not_valid_before": "c.not_valid_before", "not_valid_after": "c.not_valid_after",
    "issued_via": "c.issued_via", "username": "u.username",
}


@bp.route("/certificates", methods=["GET"])
@_require_token()
def list_certificates():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(request.args.get("per_page", 25, type=int), 200)
    search = (request.args.get("q") or "").strip()
    status_filter = (request.args.get("status") or "").lower()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    issued_via = (request.args.get("issued_via") or "").lower().strip()
    username_filter = (request.args.get("username") or "").strip()
    sort_by = _CERT_SORT_COLS.get((request.args.get("sort_by") or "id").strip(), "c.id")
    sort_order = "ASC" if (request.args.get("sort_order") or "desc").upper() == "ASC" else "DESC"

    now = datetime.now(timezone.utc)
    params = []
    where = []
    if not g.token_user.is_admin():
        where.append("c.user_id = ?")
        params.append(g.token_user.id)
    if search:
        lk = f"%{search}%"
        where.append("(c.subject LIKE ? OR c.serial LIKE ? OR COALESCE(c.common_name,'') LIKE ?)")
        params.extend([lk, lk, lk])
    if status_filter == "revoked":
        where.append("c.revoked = 1")
    elif status_filter == "valid":
        where.append("c.revoked = 0 AND c.not_valid_after > ?")
        params.append(now.isoformat())
    elif status_filter == "expired":
        where.append("c.not_valid_after <= ?")
        params.append(now.isoformat())
    if date_from:
        where.append("c.not_valid_before >= ?")
        params.append(date_from)
    if date_to:
        where.append("c.not_valid_before <= ?")
        params.append(date_to)
    if issued_via:
        where.append("c.issued_via = ?")
        params.append(issued_via)
    if username_filter:
        where.append("u.username LIKE ?")
        params.append(f"%{username_filter}%")

    where_sql = "WHERE " + " AND ".join(where) if where else ""

    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        count_sql = f"""SELECT COUNT(*) FROM certificates c
                LEFT JOIN users u ON u.id = c.user_id {where_sql}"""
        total = conn.execute(count_sql, params).fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            f"""SELECT c.id, c.subject, c.serial, c.revoked, c.issued_via,
                       c.common_name, c.keycol, c.not_valid_before, c.not_valid_after,
                       u.username
                FROM certificates c
                LEFT JOIN users u ON u.id = c.user_id
                {where_sql}
                ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?""",
            [*params, per_page, offset],
        ).fetchall()

    certs = []
    for r in rows:
        try:
            expired = datetime.fromisoformat(r["not_valid_after"]) < now if r["not_valid_after"] else False
        except Exception:
            expired = False
        certs.append({
            "id": r["id"],
            "subject": r["subject"],
            "serial": r["serial"],
            "common_name": r["common_name"],
            "keycol": r["keycol"],
            "not_valid_before": r["not_valid_before"],
            "not_valid_after": r["not_valid_after"],
            "revoked": bool(r["revoked"]),
            "expired": expired,
            "issued_via": r["issued_via"],
            "username": r["username"],
        })

    return jsonify({
        "certificates": certs,
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })


@bp.route("/certificates/<int:cert_id>", methods=["GET"])
@_require_token()
def get_certificate(cert_id):
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if g.token_user.is_admin():
            row = conn.execute(
                "SELECT * FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM certificates WHERE id = ? AND user_id = ?",
                (cert_id, g.token_user.id),
            ).fetchone()
    if not row:
        return jsonify({"error": "Certificate not found or access denied"}), 404

    cert_pem = row["cert_pem"]
    try:
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        details = {
            "serial_hex": hex(cert_obj.serial_number),
            "subject": {a.oid._name: a.value for a in cert_obj.subject},
            "issuer":  {a.oid._name: a.value for a in cert_obj.issuer},
            "not_valid_before": cert_obj.not_valid_before_utc.isoformat(),
            "not_valid_after":  cert_obj.not_valid_after_utc.isoformat(),
            "extensions": {e.oid._name: str(e.value) for e in cert_obj.extensions},
        }
    except Exception as exc:
        details = {"parse_error": str(exc)}

    return jsonify({
        "id": row["id"],
        "subject": row["subject"],
        "serial": row["serial"],
        "revoked": bool(row["revoked"]),
        "issued_via": row["issued_via"],
        "cert_pem": cert_pem,
        "details": details,
    })


@bp.route("/certificates/<int:cert_id>/download", methods=["GET"])
@_require_token()
def download_certificate(cert_id):
    fmt = request.args.get("format", "pem").lower()
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if g.token_user.is_admin():
            row = conn.execute("SELECT serial, cert_pem FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        else:
            row = conn.execute(
                "SELECT serial, cert_pem FROM certificates WHERE id = ? AND user_id = ?",
                (cert_id, g.token_user.id),
            ).fetchone()
    if not row:
        return jsonify({"error": "Certificate not found or access denied"}), 404
    return jsonify({"serial": row["serial"], "format": fmt, "cert_pem": row["cert_pem"]})


@bp.route("/certificates/sign", methods=["POST"])
@_require_token()
def sign_certificate():
    data = request.get_json(silent=True) or {}
    csr_pem = (data.get("csr_pem") or "").strip()
    csr_id = data.get("csr_id")

    if csr_id and not csr_pem:
        csr_obj_db = CSR.query.get(csr_id)
        if not csr_obj_db:
            return jsonify({"error": f"CSR id={csr_id} not found"}), 404
        if not g.token_user.is_admin() and csr_obj_db.user_id != g.token_user.id:
            return jsonify({"error": "Access denied to this CSR"}), 403
        csr_pem = csr_obj_db.csr_pem

    if not csr_pem:
        return jsonify({"error": "Provide 'csr_pem' (PEM string) or 'csr_id'"}), 400

    try:
        csr_pem = _normalize_csr_pem(csr_pem)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    policy_id = data.get("policy_id")
    no_extensions = bool(data.get("no_extensions", False))
    use_csr_extensions = bool(data.get("use_csr_extensions", False))
    validity_override = (data.get("validity_days") or "").strip()

    mgr = _mgr()
    user_id_for_policy = None if g.token_user.is_admin() else g.token_user.id
    if policy_id:
        try:
            policy = mgr.get_policy(policy_id=int(policy_id), user_id=user_id_for_policy)
        except Exception:
            policy = None
    else:
        policy = mgr.get_default_policy(user_id_for_policy)

    if not policy:
        return jsonify({"error": "No RA policy available for signing. Create or assign one first."}), 400

    if validity_override:
        try:
            validity_days = int(validity_override)
        except ValueError:
            return jsonify({"error": "validity_days must be an integer"}), 400
    else:
        try:
            validity_days = int(str(mgr.get_validity_days(policy)))
        except Exception:
            validity_days = int(DEFAULT_VALIDITY_DAYS)

    try:
        result = _sign_csr_pem(
            csr_pem=csr_pem,
            policy=policy,
            validity_days=validity_days,
            no_extensions=no_extensions,
            use_csr_extensions=use_csr_extensions,
            user_id=g.token_user.id,
            issued_via="manual",
        )
    except NotImplementedError as e:
        return jsonify({"error": str(e)}), 501
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    return jsonify(result), 201


@bp.route("/certificates/<int:cert_id>/revoke", methods=["POST"])
@_require_token()
def revoke_certificate(cert_id):
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if g.token_user.is_admin():
            row = conn.execute(
                "SELECT id, serial, subject FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id, serial, subject FROM certificates WHERE id = ? AND user_id = ?",
                (cert_id, g.token_user.id),
            ).fetchone()
        if not row:
            return jsonify({"error": "Certificate not found or access denied"}), 404
        if g.token_user.is_admin():
            conn.execute("UPDATE certificates SET revoked = 1 WHERE id = ?", (cert_id,))
        else:
            conn.execute(
                "UPDATE certificates SET revoked = 1 WHERE id = ? AND user_id = ?",
                (cert_id, g.token_user.id),
            )
        conn.commit()
        log_event("revoke", "certificate", row["serial"], g.token_user.id,
                  {"subject": row["subject"]})

    # Regenerate CRL in background (best-effort)
    try:
        from app import update_crl  # noqa: PLC0415
        update_crl()
    except Exception:
        pass

    return jsonify({"ok": True, "id": cert_id, "serial": row["serial"]})


@bp.route("/certificates/<int:cert_id>", methods=["DELETE"])
@_require_token()
def delete_certificate(cert_id):
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if g.token_user.is_admin():
            row = conn.execute(
                "SELECT serial, subject FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT serial, subject FROM certificates WHERE id = ? AND user_id = ?",
                (cert_id, g.token_user.id),
            ).fetchone()
        if not row:
            return jsonify({"error": "Certificate not found or access denied"}), 404
        if g.token_user.is_admin():
            conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
        else:
            conn.execute(
                "DELETE FROM certificates WHERE id = ? AND user_id = ?",
                (cert_id, g.token_user.id),
            )
        conn.commit()
        log_event("delete", "certificate", row["serial"], g.token_user.id,
                  {"subject": row["subject"]})

    return jsonify({"ok": True, "id": cert_id})


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

# Allowed sort columns for keys
_KEY_SORT_COLS = {
    "id": "id", "name": "name", "key_type": "key_type",
    "key_size": "key_size", "created_at": "created_at",
}


@bp.route("/keys", methods=["GET"])
@_require_token()
def list_keys():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(request.args.get("per_page", 25, type=int), 200)
    search = (request.args.get("q") or "").strip()
    key_type = (request.args.get("key_type") or "").upper().strip()
    curve_name_filter = (request.args.get("curve_name") or "").strip()
    pqc_alg_filter = (request.args.get("pqc_alg") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    sort_by = _KEY_SORT_COLS.get((request.args.get("sort_by") or "id").strip(), "id")
    sort_order = "ASC" if (request.args.get("sort_order") or "desc").upper() == "ASC" else "DESC"

    params = []
    where = []
    if not g.token_user.is_admin():
        where.append("user_id = ?")
        params.append(g.token_user.id)
    if search:
        lk = f"%{search}%"
        where.append("(name LIKE ? OR COALESCE(curve_name,'') LIKE ? OR COALESCE(pqc_alg,'') LIKE ?)")
        params.extend([lk, lk, lk])
    if key_type:
        where.append("key_type = ?")
        params.append(key_type)
    if curve_name_filter:
        where.append("curve_name LIKE ?")
        params.append(f"%{curve_name_filter}%")
    if pqc_alg_filter:
        where.append("pqc_alg LIKE ?")
        params.append(f"%{pqc_alg_filter}%")
    if date_from:
        where.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        where.append("created_at <= ?")
        params.append(date_to)

    where_sql = "WHERE " + " AND ".join(where) if where else ""
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(f"SELECT COUNT(*) FROM keys {where_sql}", params).fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT id, name, key_type, key_size, curve_name, pqc_alg, created_at, user_id "
            f"FROM keys {where_sql} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
            [*params, per_page, offset],
        ).fetchall()

    return jsonify({
        "keys": [
            {
                "id": r["id"], "name": r["name"], "key_type": r["key_type"],
                "key_size": r["key_size"], "curve_name": r["curve_name"],
                "pqc_alg": r["pqc_alg"],
                "created_at": r["created_at"],
                "user_id": r["user_id"],
            }
            for r in rows
        ],
        "page": page, "per_page": per_page,
        "total": total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })


@bp.route("/keys", methods=["POST"])
@_require_token()
def generate_key():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    key_type = (data.get("key_type") or "EC").upper()
    key_size = str(data.get("key_size") or "2048")
    curve_name = (data.get("curve_name") or "prime256v1").strip()
    pqc_alg = (data.get("pqc_alg") or "mldsa44").strip()

    if not name:
        return jsonify({"error": "'name' is required"}), 400
    if key_type not in ("RSA", "EC", "PQC"):
        return jsonify({"error": "key_type must be RSA, EC, or PQC"}), 400

    priv_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    priv_path = priv_f.name
    priv_f.close()
    pub_path = priv_path + ".pub.pem"

    try:
        if key_type == "RSA":
            cmd = ["openssl", "genrsa", "-out", priv_path, key_size]
        elif key_type == "EC":
            cmd = ["openssl", "ecparam", "-name", curve_name, "-genkey", "-noout", "-out", priv_path]
        else:  # PQC
            if not feature_enabled("pqc_keys"):
                return jsonify({"error": "PQC keys require the Enterprise edition"}), 403
            cmd = ["openssl", "genpkey", "-algorithm", pqc_alg]
            cmd.extend(get_provider_args())
            cmd.extend(["-out", priv_path])

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return jsonify({"error": f"Key generation failed: {res.stderr.strip()}"}), 500

        pub_cmd = ["openssl", "pkey", "-in", priv_path, "-pubout"]
        pub_cmd.extend(get_provider_args())
        pub_cmd.extend(["-out", pub_path])
        res = subprocess.run(pub_cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return jsonify({"error": f"Public key extraction failed: {res.stderr.strip()}"}), 500

        with open(priv_path) as f:
            priv_data = f.read()
        with open(pub_path) as f:
            pub_data = f.read()
    finally:
        for p in (priv_path, pub_path):
            try:
                os.unlink(p)
            except OSError:
                pass

    new_key = Key(
        name=name,
        key_type=key_type,
        key_size=int(key_size) if key_type == "RSA" else None,
        curve_name=curve_name if key_type == "EC" else None,
        pqc_alg=pqc_alg if key_type == "PQC" else None,
        private_key=priv_data,
        public_key=pub_data,
        created_at=datetime.utcnow(),
        user_id=g.token_user.id,
    )
    db.session.add(new_key)
    db.session.commit()
    log_event("create", "key", name, g.token_user.id, {"key_type": key_type})

    return jsonify({
        "id": new_key.id,
        "name": new_key.name,
        "key_type": new_key.key_type,
        "key_size": new_key.key_size,
        "curve_name": new_key.curve_name,
        "pqc_alg": new_key.pqc_alg,
        "public_key": pub_data,
    }), 201


@bp.route("/keys/<int:key_id>", methods=["GET"])
@_require_token()
def get_key(key_id):
    if g.token_user.is_admin():
        k = Key.query.get(key_id)
    else:
        k = Key.query.filter_by(id=key_id, user_id=g.token_user.id).first()
    if not k:
        return jsonify({"error": "Key not found or access denied"}), 404
    include_private = request.args.get("include_private", "false").lower() == "true"
    result = {
        "id": k.id,
        "name": k.name,
        "key_type": k.key_type,
        "key_size": k.key_size,
        "curve_name": k.curve_name,
        "pqc_alg": k.pqc_alg,
        "public_key": k.public_key,
        "created_at": k.created_at.isoformat() if k.created_at else None,
    }
    if include_private:
        result["private_key"] = k.private_key
    return jsonify(result)


@bp.route("/keys/<int:key_id>", methods=["DELETE"])
@_require_token()
def delete_key(key_id):
    if g.token_user.is_admin():
        k = Key.query.get(key_id)
    else:
        k = Key.query.filter_by(id=key_id, user_id=g.token_user.id).first()
    if not k:
        return jsonify({"error": "Key not found or access denied"}), 404
    name = k.name
    db.session.delete(k)
    db.session.commit()
    log_event("delete", "key", name, g.token_user.id, {})
    return jsonify({"ok": True, "id": key_id})


# ---------------------------------------------------------------------------
# CSRs
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------

# Allowed sort columns for CSRs
_CSR_SORT_COLS = {
    "id": "id", "name": "name", "source": "source", "created_at": "created_at",
    "key_id": "key_id", "profile_id": "profile_id",
}


@bp.route("/csrs", methods=["GET"])
@_require_token()
def list_csrs():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(request.args.get("per_page", 25, type=int), 200)
    search = (request.args.get("q") or "").strip()
    source_filter = (request.args.get("source") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    sort_by = _CSR_SORT_COLS.get((request.args.get("sort_by") or "id").strip(), "id")
    sort_order = "ASC" if (request.args.get("sort_order") or "desc").upper() == "ASC" else "DESC"

    params = []
    where = []
    if not g.token_user.is_admin():
        where.append("user_id = ?")
        params.append(g.token_user.id)
    if search:
        where.append("name LIKE ?")
        params.append(f"%{search}%")
    if source_filter:
        where.append("source = ?")
        params.append(source_filter)
    if date_from:
        where.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        where.append("created_at <= ?")
        params.append(date_to)

    where_sql = "WHERE " + " AND ".join(where) if where else ""
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(f"SELECT COUNT(*) FROM csrs {where_sql}", params).fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT id, name, key_id, profile_id, source, created_at "
            f"FROM csrs {where_sql} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
            [*params, per_page, offset],
        ).fetchall()

    return jsonify({
        "csrs": [
            {
                "id": r["id"], "name": r["name"], "key_id": r["key_id"],
                "profile_id": r["profile_id"], "source": r["source"],
                "created_at": r["created_at"],
            }
            for r in rows
        ],
        "page": page, "per_page": per_page,
        "total": total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })


@bp.route("/csrs/generate", methods=["POST"])
@_require_token()
def generate_csr():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    key_id = data.get("key_id")
    profile_id = data.get("profile_id")
    if not name or not key_id or not profile_id:
        return jsonify({"error": "'name', 'key_id', and 'profile_id' are required"}), 400

    if g.token_user.is_admin():
        key_obj = Key.query.get(key_id)
    else:
        key_obj = Key.query.filter_by(id=key_id, user_id=g.token_user.id).first()
    if not key_obj:
        return jsonify({"error": "Key not found or access denied"}), 404

    profile_obj = Profile.query.get(profile_id)
    if not profile_obj:
        return jsonify({"error": "Profile not found"}), 404

    cfg_f = tempfile.NamedTemporaryFile(delete=False, suffix=".cnf", mode="w", encoding="utf-8")
    cfg_f.write(profile_obj.content or "")
    cfg_f.close()
    key_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w")
    key_f.write(key_obj.private_key)
    key_f.close()
    csr_f = tempfile.NamedTemporaryFile(delete=False, suffix=".csr")
    csr_f.close()

    try:
        cmd = ["openssl", "req", "-new"]
        cmd.extend(get_provider_args())
        cmd.extend(["-config", cfg_f.name, "-key", key_f.name, "-out", csr_f.name])
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return jsonify({"error": f"CSR generation failed: {res.stderr.strip()}"}), 500
        with open(csr_f.name) as f:
            csr_pem = f.read()
    finally:
        for p in (cfg_f.name, key_f.name, csr_f.name):
            try:
                os.unlink(p)
            except OSError:
                pass

    new_csr = CSR(
        name=name,
        key_id=key_obj.id,
        profile_id=profile_obj.id,
        csr_pem=csr_pem,
        source="generated",
        created_at=datetime.utcnow(),
        user_id=g.token_user.id,
    )
    db.session.add(new_csr)
    db.session.commit()
    log_event("create", "csr", name, g.token_user.id, {})

    return jsonify({"id": new_csr.id, "name": name, "csr_pem": csr_pem}), 201


@bp.route("/csrs/import", methods=["POST"])
@_require_token()
def import_csr():
    data = request.get_json(silent=True) or {}
    csr_pem = (data.get("csr_pem") or "").strip()
    name = (data.get("name") or "").strip()
    if not csr_pem:
        return jsonify({"error": "'csr_pem' is required"}), 400

    try:
        csr_pem = _normalize_csr_pem(csr_pem)
        csr_obj = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not name:
        attrs = csr_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        name = attrs[0].value if attrs else "imported-csr"

    new_csr = CSR(
        name=name,
        key_id=0,
        profile_id=0,
        csr_pem=csr_pem,
        source="imported",
        created_at=datetime.utcnow(),
        user_id=g.token_user.id,
    )
    db.session.add(new_csr)
    db.session.commit()
    log_event("create", "csr", name, g.token_user.id, {"source": "imported"})

    return jsonify({"id": new_csr.id, "name": name, "csr_pem": csr_pem}), 201


@bp.route("/csrs/<int:csr_id>", methods=["GET"])
@_require_token()
def get_csr(csr_id):
    if g.token_user.is_admin():
        c = CSR.query.get(csr_id)
    else:
        c = CSR.query.filter_by(id=csr_id, user_id=g.token_user.id).first()
    if not c:
        return jsonify({"error": "CSR not found or access denied"}), 404
    return jsonify({
        "id": c.id, "name": c.name, "key_id": c.key_id,
        "profile_id": c.profile_id, "source": c.source,
        "csr_pem": c.csr_pem,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    })


@bp.route("/csrs/<int:csr_id>", methods=["DELETE"])
@_require_token()
def delete_csr(csr_id):
    if g.token_user.is_admin():
        c = CSR.query.get(csr_id)
    else:
        c = CSR.query.filter_by(id=csr_id, user_id=g.token_user.id).first()
    if not c:
        return jsonify({"error": "CSR not found or access denied"}), 404
    name = c.name
    db.session.delete(c)
    db.session.commit()
    log_event("delete", "csr", name, g.token_user.id, {})
    return jsonify({"ok": True, "id": csr_id})


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@bp.route("/profiles", methods=["GET"])
@_require_token()
def list_profiles():
    if g.token_user.is_admin():
        profiles = Profile.query.order_by(Profile.id.desc()).all()
    else:
        profiles = Profile.query.filter_by(user_id=g.token_user.id).order_by(Profile.id.desc()).all()
    return jsonify({
        "profiles": [
            {
                "id": p.id, "name": p.name, "template_name": p.template_name,
                "profile_type": p.profile_type,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "user_id": p.user_id,
            }
            for p in profiles
        ]
    })


@bp.route("/profiles/<int:profile_id>", methods=["GET"])
@_require_token()
def get_profile(profile_id):
    if g.token_user.is_admin():
        p = Profile.query.get(profile_id)
    else:
        p = Profile.query.filter_by(id=profile_id, user_id=g.token_user.id).first()
    if not p:
        return jsonify({"error": "Profile not found or access denied"}), 404
    return jsonify({
        "id": p.id, "name": p.name, "template_name": p.template_name,
        "profile_type": p.profile_type, "content": p.content,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    })


@bp.route("/profiles", methods=["POST"])
@_require_token()
def create_profile():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    content = (data.get("content") or "").strip()
    if not name or not content:
        return jsonify({"error": "'name' and 'content' are required"}), 400
    if Profile.query.filter_by(name=name).first():
        return jsonify({"error": f"Profile '{name}' already exists"}), 409
    p = Profile(
        name=name,
        template_name=data.get("template_name") or name,
        profile_type=data.get("profile_type") or "",
        content=content,
        created_at=datetime.utcnow(),
        user_id=g.token_user.id,
    )
    db.session.add(p)
    db.session.commit()
    log_event("create", "profile", name, g.token_user.id, {})
    return jsonify({"id": p.id, "name": p.name}), 201


@bp.route("/profiles/<int:profile_id>", methods=["PUT"])
@_require_token()
def update_profile(profile_id):
    if g.token_user.is_admin():
        p = Profile.query.get(profile_id)
    else:
        p = Profile.query.filter_by(id=profile_id, user_id=g.token_user.id).first()
    if not p:
        return jsonify({"error": "Profile not found or access denied"}), 404
    data = request.get_json(silent=True) or {}
    if "content" in data:
        p.content = data["content"]
    if "profile_type" in data:
        p.profile_type = data["profile_type"]
    db.session.commit()
    log_event("update", "profile", p.name, g.token_user.id, {})
    return jsonify({"ok": True, "id": p.id, "name": p.name})


@bp.route("/profiles/<int:profile_id>", methods=["DELETE"])
@_require_token()
def delete_profile(profile_id):
    if g.token_user.is_admin():
        p = Profile.query.get(profile_id)
    else:
        p = Profile.query.filter_by(id=profile_id, user_id=g.token_user.id).first()
    if not p:
        return jsonify({"error": "Profile not found or access denied"}), 404
    name = p.name
    db.session.delete(p)
    db.session.commit()
    log_event("delete", "profile", name, g.token_user.id, {})
    return jsonify({"ok": True, "id": profile_id})


# ---------------------------------------------------------------------------
# RA Policies
# ---------------------------------------------------------------------------

@bp.route("/ra_policies", methods=["GET"])
@_require_token()
def list_ra_policies():
    mgr = _mgr()
    if g.token_user.is_admin():
        policies = mgr.list_all_policies()
    else:
        policies = mgr.list_policies_for_user(g.token_user.id)
    return jsonify({"ra_policies": policies})


@bp.route("/ra_policies/<int:policy_id>", methods=["GET"])
@_require_token()
def get_ra_policy(policy_id):
    mgr = _mgr()
    user_id = None if g.token_user.is_admin() else g.token_user.id
    p = mgr.get_policy(policy_id=policy_id, user_id=user_id)
    if not p:
        return jsonify({"error": "Policy not found or access denied"}), 404
    return jsonify(p)


@bp.route("/ra_policies", methods=["POST"])
@_require_token(admin_only=True)
def create_ra_policy():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "'name' is required"}), 400
    validity = str(data.get("validity_period") or DEFAULT_VALIDITY_DAYS)
    ext_config = (data.get("ext_config") or "").strip()
    policy_type = "system" if data.get("is_system") else "user"
    est_default = bool(data.get("is_est_default", False))
    scep_default = bool(data.get("is_scep_default", False))

    mgr = _mgr()
    try:
        pid = mgr.upsert_policy(
            name=name,
            ext_config=ext_config,
            validity_period=validity,
            policy_type=policy_type,
            est_default=est_default,
            scep_default=scep_default,
            user_id=g.token_user.id,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    policy = mgr.get_policy(policy_id=pid)
    log_event("create", "ra_policy", name, g.token_user.id, {})
    return jsonify(policy), 201


@bp.route("/ra_policies/<int:policy_id>", methods=["PUT"])
@_require_token(admin_only=True)
def update_ra_policy(policy_id):
    data = request.get_json(silent=True) or {}
    mgr = _mgr()
    existing = mgr.get_policy(policy_id=policy_id)
    if not existing:
        return jsonify({"error": "Policy not found"}), 404
    ext_config = data.get("ext_config", existing.get("ext_config") or "")
    validity = str(data.get("validity_period") or existing.get("validity_period") or DEFAULT_VALIDITY_DAYS)
    policy_type = data.get("policy_type") or existing.get("type")
    est_default = bool(data.get("is_est_default", existing.get("is_est_default", 0)))
    scep_default = bool(data.get("is_scep_default", existing.get("is_scep_default", 0)))
    mgr.update_policy(policy_id, ext_config, validity,
                      policy_type=policy_type, est_default=est_default, scep_default=scep_default)
    log_event("update", "ra_policy", existing["name"], g.token_user.id, {})
    return jsonify({"ok": True, "id": policy_id})


@bp.route("/ra_policies/<int:policy_id>", methods=["DELETE"])
@_require_token(admin_only=True)
def delete_ra_policy(policy_id):
    mgr = _mgr()
    existing = mgr.get_policy(policy_id=policy_id)
    if not existing:
        return jsonify({"error": "Policy not found"}), 404
    mgr.delete_policy(policy_id)
    log_event("delete", "ra_policy", existing["name"], g.token_user.id, {})
    return jsonify({"ok": True, "id": policy_id})


# ---------------------------------------------------------------------------
# Users (admin only)
# ---------------------------------------------------------------------------

# Users (admin only)
# ---------------------------------------------------------------------------

# Allowed sort columns for users
_USER_SORT_COLS = {
    "id": "id", "username": "username", "role": "role",
    "status": "status", "created_at": "created_at", "last_login": "last_login",
}


@bp.route("/users", methods=["GET"])
@_require_token(admin_only=True)
def list_users():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(request.args.get("per_page", 25, type=int), 200)
    search = (request.args.get("q") or "").strip()
    role_filter = (request.args.get("role") or "").strip().lower()
    status_filter = (request.args.get("status") or "").strip().lower()
    sort_by = _USER_SORT_COLS.get((request.args.get("sort_by") or "username").strip(), "username")
    sort_order = "ASC" if (request.args.get("sort_order") or "asc").upper() == "ASC" else "DESC"

    params = []
    where = []
    if search:
        lk = f"%{search}%"
        where.append("(username LIKE ? OR email LIKE ?)")
        params.extend([lk, lk])
    if role_filter:
        where.append("role = ?")
        params.append(role_filter)
    if status_filter:
        where.append("status = ?")
        params.append(status_filter)

    where_sql = "WHERE " + " AND ".join(where) if where else ""
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(f"SELECT COUNT(*) FROM users {where_sql}", params).fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT id, username, email, role, status, auth_source, created_at, last_login "
            f"FROM users {where_sql} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
            [*params, per_page, offset],
        ).fetchall()

    return jsonify({
        "users": [
            {
                "id": r["id"], "username": r["username"], "email": r["email"],
                "role": r["role"], "status": r["status"], "auth_source": r["auth_source"],
                "created_at": r["created_at"], "last_login": r["last_login"],
            }
            for r in rows
        ],
        "page": page, "per_page": per_page,
        "total": total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })


@bp.route("/users/<int:user_id>", methods=["GET"])
@_require_token(admin_only=True)
def get_user_detail(user_id):
    u = get_user_by_id(user_id)
    if not u:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": u.id, "username": u.username, "email": u.email,
        "role": u.role, "status": u.status, "auth_source": u.auth_source,
    })


@bp.route("/users", methods=["POST"])
@_require_token(admin_only=True)
def create_user():
    from werkzeug.security import generate_password_hash
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    role = (data.get("role") or "user").strip().lower()
    email = (data.get("email") or "").strip() or None
    if not username or not password:
        return jsonify({"error": "'username' and 'password' are required"}), 400
    if role not in ("user", "admin"):
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400
    try:
        user_id = create_user_db(username, password, role, email, status="active")
    except Exception as e:
        return jsonify({"error": f"Failed to create user: {e}"}), 409
    log_event("create", "user", username, g.token_user.id, {"role": role})
    return jsonify({"id": user_id, "username": username, "role": role}), 201


@bp.route("/users/<int:user_id>", methods=["DELETE"])
@_require_token(admin_only=True)
def delete_user(user_id):
    u = get_user_by_id(user_id)
    if not u:
        return jsonify({"error": "User not found"}), 404
    if user_id == g.token_user.id:
        return jsonify({"error": "Cannot delete your own account"}), 400
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    log_event("delete", "user", u.username, g.token_user.id, {})
    return jsonify({"ok": True, "id": user_id})


def _user_action(user_id, action):
    u = get_user_by_id(user_id)
    if not u:
        return jsonify({"error": "User not found"}), 404
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        if action == "approve":
            conn.execute("UPDATE users SET status='active' WHERE id=?", (user_id,))
        elif action == "toggle_active":
            new_status = "disabled" if u.status == "active" else "active"
            conn.execute("UPDATE users SET status=? WHERE id=?", (new_status, user_id))
        conn.commit()
    log_event("update", "user", u.username, g.token_user.id, {"action": action})
    return jsonify({"ok": True, "id": user_id, "action": action})


@bp.route("/users/<int:user_id>/approve", methods=["POST"])
@_require_token(admin_only=True)
def approve_user(user_id):
    return _user_action(user_id, "approve")


@bp.route("/users/<int:user_id>/toggle_active", methods=["POST"])
@_require_token(admin_only=True)
def toggle_user_active(user_id):
    return _user_action(user_id, "toggle_active")


@bp.route("/users/<int:user_id>/change_role", methods=["POST"])
@_require_token(admin_only=True)
def change_user_role(user_id):
    if user_id == g.token_user.id:
        return jsonify({"error": "Cannot change your own role"}), 400
    data = request.get_json(silent=True) or {}
    role = (data.get("role") or "").strip().lower()
    if role not in ("user", "admin"):
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400
    u = get_user_by_id(user_id)
    if not u:
        return jsonify({"error": "User not found"}), 404
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        conn.commit()
    log_event("update", "user", u.username, g.token_user.id, {"role": role})
    return jsonify({"ok": True, "id": user_id, "role": role})


@bp.route("/users/<int:user_id>/reset_password", methods=["POST"])
@_require_token(admin_only=True)
def reset_user_password(user_id):
    from werkzeug.security import generate_password_hash
    data = request.get_json(silent=True) or {}
    new_password = (data.get("password") or "").strip()
    if not new_password or len(new_password) < 8:
        return jsonify({"error": "'password' must be at least 8 characters"}), 400
    u = get_user_by_id(user_id)
    if not u:
        return jsonify({"error": "User not found"}), 404
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                     (generate_password_hash(new_password), user_id))
        conn.commit()
    log_event("update", "user", u.username, g.token_user.id, {"action": "reset_password"})
    return jsonify({"ok": True, "id": user_id})


# ---------------------------------------------------------------------------
# API Tokens
# ---------------------------------------------------------------------------

@bp.route("/tokens", methods=["GET"])
@_require_token()
def list_tokens():
    if not feature_enabled("api_tokens"):
        return jsonify({"error": "Not available"}), 404
    from enterprise.tokens import list_api_tokens
    user_id = None if g.token_user.is_admin() else g.token_user.id
    tokens = list_api_tokens(user_id)
    return jsonify({"tokens": tokens})


@bp.route("/tokens", methods=["POST"])
@_require_token()
def create_token():
    if not feature_enabled("api_tokens"):
        return jsonify({"error": "Not available"}), 404
    from enterprise.tokens import create_api_token
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    validity = (data.get("validity") or "").strip()
    try:
        length = int(data.get("length") or 64)
    except (TypeError, ValueError):
        length = 64
    if not name:
        return jsonify({"error": "'name' is required"}), 400
    raw_token, record = create_api_token(g.token_user.id, name, validity or None, length)
    return jsonify({
        "raw_token": raw_token,
        "id": record["id"],
        "name": name,
        "expires_at": record["expires_at"].strftime("%Y-%m-%d %H:%M:%S") if record.get("expires_at") else None,
        "warning": "Store this token securely — it will not be shown again.",
    }), 201


@bp.route("/tokens/<int:token_id>", methods=["DELETE"])
@_require_token()
def delete_token(token_id):
    if not feature_enabled("api_tokens"):
        return jsonify({"error": "Not available"}), 404
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT user_id FROM api_tokens WHERE id=?", (token_id,)).fetchone()
        if not row:
            return jsonify({"error": "Token not found"}), 404
        if not g.token_user.is_admin() and row["user_id"] != g.token_user.id:
            return jsonify({"error": "Access denied"}), 403
        conn.execute("DELETE FROM api_tokens WHERE id=?", (token_id,))
        conn.commit()
    return jsonify({"ok": True, "id": token_id})


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

# Allowed sort columns for events
_EVENT_SORT_COLS = {
    "timestamp": "timestamp", "event_type": "event_type",
    "resource_type": "resource_type", "resource_name": "resource_name",
}


@bp.route("/events", methods=["GET"])
@_require_token()
def list_events():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(request.args.get("per_page", 50, type=int), 500)
    search = (request.args.get("q") or "").strip()
    resource_type = request.args.get("resource_type", "").strip()
    event_type = request.args.get("event_type", "").strip()
    resource_name = request.args.get("resource_name", "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    sort_by = _EVENT_SORT_COLS.get((request.args.get("sort_by") or "timestamp").strip(), "timestamp")
    sort_order = "ASC" if (request.args.get("sort_order") or "desc").upper() == "ASC" else "DESC"

    params = []
    where = ["1=1"]
    if not g.token_user.is_admin():
        where.append("user_id = ?")
        params.append(g.token_user.id)
        where.append("NOT (resource_type = 'user' AND (event_type = 'create' OR event_type = 'delete'))")
    if search:
        where.append("resource_name LIKE ?")
        params.append(f"%{search}%")
    if resource_type:
        where.append("resource_type = ?")
        params.append(resource_type)
    if event_type:
        where.append("event_type = ?")
        params.append(event_type)
    if resource_name:
        where.append("resource_name LIKE ?")
        params.append(f"%{resource_name}%")
    if date_from:
        where.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        where.append("timestamp <= ?")
        params.append(date_to)

    where_sql = "WHERE " + " AND ".join(where)
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(f"SELECT COUNT(*) FROM events {where_sql}", params).fetchone()[0]
        offset = (page - 1) * per_page
        rows = conn.execute(
            f"SELECT * FROM events {where_sql} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
            [*params, per_page, offset],
        ).fetchall()

    events = []
    for r in rows:
        try:
            details = json.loads(r["details"]) if r["details"] else {}
        except Exception:
            details = {}
        events.append({
            "event_id": r["event_id"] if "event_id" in r.keys() else r["rowid"],
            "event_type": r["event_type"],
            "resource_type": r["resource_type"],
            "resource_name": r["resource_name"],
            "user_id": r["user_id"],
            "timestamp": r["timestamp"],
            "details": details,
        })

    return jsonify({
        "events": events, "page": page, "per_page": per_page,
        "total": total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    })


@bp.route("/events/<int:event_id>", methods=["GET"])
@_require_token()
def get_event(event_id):
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM events WHERE rowid=? OR event_id=?",
                           (event_id, event_id)).fetchone()
    if not row:
        return jsonify({"error": "Event not found"}), 404
    if not g.token_user.is_admin() and row["user_id"] != g.token_user.id:
        return jsonify({"error": "Access denied"}), 403
    try:
        details = json.loads(row["details"]) if row["details"] else {}
    except Exception:
        details = {}
    return jsonify({
        "event_id": event_id,
        "event_type": row["event_type"],
        "resource_type": row["resource_type"],
        "resource_name": row["resource_name"],
        "user_id": row["user_id"],
        "timestamp": row["timestamp"],
        "details": details,
    })


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@bp.route("/dashboard", methods=["GET"])
@_require_token()
def dashboard_stats():
    now = datetime.now(timezone.utc)
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        if g.token_user.is_admin():
            rows = conn.execute(
                "SELECT cert_pem, revoked, issued_via FROM certificates"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT cert_pem, revoked, issued_via FROM certificates WHERE user_id=?",
                (g.token_user.id,),
            ).fetchall()

    summary = {"total": 0, "valid": 0, "expired": 0, "revoked": 0}
    enrollment = {"ui": 0, "est": 0, "scep": 0, "api": 0}
    for cert_pem, revoked, issued_via in rows:
        summary["total"] += 1
        if revoked:
            summary["revoked"] += 1
        else:
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                if cert.not_valid_after_utc < now:
                    summary["expired"] += 1
                else:
                    summary["valid"] += 1
            except Exception:
                summary["expired"] += 1
        via = (issued_via or "unknown").lower()
        if via in enrollment:
            enrollment[via] += 1
    return jsonify({"summary": summary, "enrollment": enrollment})


@bp.route("/dashboard/activity", methods=["GET"])
@_require_token()
def dashboard_activity():
    limit = min(request.args.get("limit", 500, type=int), 5000)
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if g.token_user.is_admin():
            rows = conn.execute(
                "SELECT event_type, resource_type, resource_name, timestamp FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT event_type, resource_type, resource_name, timestamp FROM events WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
                (g.token_user.id, limit),
            ).fetchall()
    return jsonify({
        "events": [dict(r) for r in rows]
    })


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------

@bp.route("/inspect", methods=["POST"])
@_require_token()
def inspect_pem():
    data = request.get_json(silent=True) or {}
    pem = (data.get("pem") or "").strip()
    if not pem:
        return jsonify({"error": "'pem' is required"}), 400

    import inspect_logic as il

    results = {}
    if "BEGIN CERTIFICATE" in pem and "REQUEST" not in pem:
        try:
            results = il.inspect_pem(pem, logger=current_app.logger)
            results["detected_type"] = "certificate"
        except Exception as e:
            results = {"error": str(e), "detected_type": "certificate"}
    elif "BEGIN CERTIFICATE REQUEST" in pem or "BEGIN NEW CERTIFICATE REQUEST" in pem:
        try:
            results = il.inspect_pem(pem, logger=current_app.logger)
            results["detected_type"] = "csr"
        except Exception as e:
            results = {"error": str(e), "detected_type": "csr"}
    elif "PRIVATE KEY" in pem or "PUBLIC KEY" in pem:
        try:
            results = il.inspect_pem(pem, logger=current_app.logger)
            results["detected_type"] = "key"
        except Exception as e:
            results = {"error": str(e), "detected_type": "key"}
    else:
        try:
            results = il.inspect_pem(pem, logger=current_app.logger)
            results["detected_type"] = "unknown"
        except Exception as e:
            results = {"error": str(e), "detected_type": "unknown"}

    return jsonify(results)


# ---------------------------------------------------------------------------
# CA / VA
# ---------------------------------------------------------------------------

@bp.route("/ca", methods=["GET"])
@_require_token()
def ca_info():
    try:
        with open(current_app.config["SUBCA_CERT_PATH"], "rb") as f:
            cert_pem = f.read().decode("utf-8")
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        return jsonify({
            "subject": {a.oid._name: a.value for a in cert.subject},
            "issuer":  {a.oid._name: a.value for a in cert.issuer},
            "serial":  hex(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after":  cert.not_valid_after_utc.isoformat(),
            "ca_mode": current_app.config.get("CA_MODE", "unknown"),
            "cert_pem": cert_pem,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/va", methods=["GET"])
@_require_token()
def va_info():
    crl_path = current_app.config.get("CRL_PATH", "")
    result = {"crl_path": crl_path, "crl_exists": os.path.isfile(crl_path)}
    if result["crl_exists"]:
        result["crl_size_bytes"] = os.path.getsize(crl_path)
        result["crl_mtime"] = datetime.fromtimestamp(os.path.getmtime(crl_path)).isoformat()
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        row = conn.execute("SELECT COUNT(*) FROM certificates WHERE revoked=1").fetchone()
        result["revoked_count"] = row[0]
    return jsonify(result)


# ---------------------------------------------------------------------------
# Config & Logs (admin only)
# ---------------------------------------------------------------------------

@bp.route("/config", methods=["GET"])
@_require_token(admin_only=True)
def get_config():
    """Return a non-sensitive subset of the live server config."""
    safe_keys = {
        "CA_MODE", "SCEP_ENABLED", "OCSP_HASH_ALGORITHM",
        "VAULT_ENABLED", "LDAP_ENABLED", "ALLOW_SELF_REGISTRATION",
        "SHOW_LEGACY_PATHS", "APP_EDITION", "PRODUCT_NAME",
        "SERVER_DNS_NAME", "MAX_IDLE_TIME",
    }
    conf = {k: current_app.config.get(k) for k in safe_keys if current_app.config.get(k) is not None}
    return jsonify(conf)


@bp.route("/logs", methods=["GET"])
@_require_token(admin_only=True)
def get_logs():
    n = min(request.args.get("lines", 200, type=int), 2000)
    log_file = current_app.config.get("LOG_FILE", "")
    if not log_file or not os.path.isfile(log_file):
        return jsonify({"error": "Log file not found", "lines": []}), 404
    try:
        with open(log_file, "rb") as f:
            f.seek(0, 2)
            end = f.tell()
            buf = b""
            pos = end
            chunk = 8192
            while pos > 0 and buf.count(b"\n") <= n:
                read = min(chunk, pos)
                pos -= read
                f.seek(pos)
                buf = f.read(read) + buf
            lines = buf.decode("utf-8", errors="replace").splitlines()[-n:]
    except Exception as e:
        return jsonify({"error": str(e), "lines": []}), 500
    return jsonify({"lines": lines, "count": len(lines)})
