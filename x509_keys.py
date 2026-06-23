import os
import io
import subprocess
import tempfile
import shutil
import getpass
from urllib.parse import unquote
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, send_file, make_response, jsonify, abort
from flask_login import login_required, current_user
from extensions import db
from openssl_utils import get_provider_args, is_pqc_available
from edition import feature_enabled

x509_keys_bp = Blueprint("keys", __name__, template_folder="html_templates")

PQC_ALGORITHM_CHOICES = [
    ("mldsa44", "mldsa44 (Dilithium2 / NIST L1)"),
    ("mldsa65", "mldsa65 (Dilithium3 / NIST L3)"),
    ("mldsa87", "mldsa87 (Dilithium5 / NIST L5)"),
    ("p384_mldsa65", "P-384 / ML-DSA-65 Composite"),
]

PQC_ALGORITHM_LABELS = dict(PQC_ALGORITHM_CHOICES)
PQC_OID_TO_NAME = {
    "2.16.840.1.101.3.4.3.17": "mldsa44",
    "1.3.6.1.4.1.2.267.7.4.4": "mldsa44",
    "1.3.6.1.4.1.2.267.7.6.5": "mldsa65",
    "1.3.6.1.4.1.2.267.7.8.7": "mldsa87",
}


def get_pqc_algorithm_label(pqc_alg):
    return PQC_ALGORITHM_LABELS.get(pqc_alg, pqc_alg)


def normalize_key_type(key_type):
    value = (key_type or "").strip()
    if value in ("RSA", "EC", "PQC"):
        return value
    if value in PQC_OID_TO_NAME:
        return "PQC"
    return value


def derive_pqc_label_from_key(key_obj):
    normalized = normalize_key_type(getattr(key_obj, "key_type", ""))
    if normalized != "PQC":
        return None
    pqc_alg = getattr(key_obj, "pqc_alg", None)
    if pqc_alg:
        return get_pqc_algorithm_label(pqc_alg)
    raw_key_type = (getattr(key_obj, "key_type", "") or "").strip()
    if raw_key_type in PQC_OID_TO_NAME:
        return get_pqc_algorithm_label(PQC_OID_TO_NAME[raw_key_type])
    return "PQC"


def _extract_api_token():
    raw_token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        raw_token = auth_header.split(" ", 1)[1].strip()
    if raw_token:
        return raw_token
    if request.headers.get("X-API-Token"):
        return request.headers.get("X-API-Token").strip()
    if request.args.get("token"):
        return request.args.get("token").strip()
    if request.is_json and isinstance(request.json, dict) and request.json.get("token"):
        return str(request.json.get("token")).strip()
    return None


def _lookup_key_for_token(key_name):
    if not feature_enabled("api_tokens"):
        abort(404)

    from users import verify_api_token
    from user_models import get_user_by_id

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
        return None, (jsonify({"error": "Key name is required"}), 400)

    query = Key.query.filter_by(name=normalized_name)
    if not token_user.is_admin():
        query = query.filter_by(user_id=token_info["user_id"])

    key_obj = query.order_by(Key.created_at.desc(), Key.id.desc()).first()
    if not key_obj:
        return None, (jsonify({"error": f"Key '{normalized_name}' not found"}), 404)

    return key_obj, token_info


def _api_key_response(pem_text, key_obj, key_part):
    response = make_response(pem_text)
    response.headers["Content-Type"] = "application/x-pem-file; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{key_obj.name}_{key_part}.pem"'
    response.headers["X-Key-Id"] = str(key_obj.id)
    response.headers["X-Key-Name"] = key_obj.name
    response.headers["X-Key-Type"] = key_obj.key_type
    return response

class Key(db.Model):
    __tablename__ = "keys"
    id         = db.Column(db.Integer,   primary_key=True)
    name       = db.Column(db.String(255), nullable=False)
    key_type   = db.Column(db.String(10),  nullable=False)  # "RSA", "EC" or "PQC"
    key_size   = db.Column(db.Integer,     nullable=True)   # for RSA
    curve_name = db.Column(db.String(50),  nullable=True)   # for EC
    pqc_alg    = db.Column(db.String(20),  nullable=True)   # for PQC, e.g. "mldsa44"
    private_key= db.Column(db.Text,        nullable=False)
    public_key = db.Column(db.Text,        nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id    = db.Column(db.Integer, nullable=True)  # Multi-tenancy


@x509_keys_bp.route("/generate", methods=["GET", "POST"])
@login_required
def generate_key():
    pqc_enabled = feature_enabled("pqc_keys")
    pqc_available = is_pqc_available()
    if request.method == "POST":
        key_name = request.form.get("key_name")
        if not key_name:
            flash("Key name is required.", "error")
            return redirect(url_for("keys.generate_key"))

        key_type = request.form.get("key_type")
        key_size = None
        curve_name = None
        pqc_alg   = None
        # temp file for private key
        priv_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        priv_path = priv_f.name
        priv_f.close()

        try:
            if key_type == "RSA":
                key_size = request.form.get("key_size", "2048")
                cmd = ["openssl", "genrsa", "-out", priv_path, key_size]

            elif key_type == "EC":
                curve_name = request.form.get("curve", "prime256v1")
                cmd = ["openssl", "ecparam", "-name", curve_name, "-genkey",
                       "-noout", "-out", priv_path]

            elif key_type == "PQC":
                if not pqc_enabled:
                    flash("PQC key generation is available in Enterprise edition only.", "error")
                    os.unlink(priv_path)
                    return redirect(url_for("keys.generate_key"))
                if not pqc_available:
                    flash("PQC key generation is unavailable (oqs-provider not installed).", "error")
                    os.unlink(priv_path)
                    return redirect(url_for("keys.generate_key"))
                # pull the PQC algorithm choice
                pqc_alg = request.form.get("pqc_alg", "mldsa44")
                if pqc_alg not in PQC_ALGORITHM_LABELS:
                    flash("Invalid PQC algorithm selected.", "error")
                    os.unlink(priv_path)
                    return redirect(url_for("keys.generate_key"))
                cmd = ["openssl", "genpkey", "-algorithm", pqc_alg]
                # Add provider args only if oqsprovider is available
                cmd.extend(get_provider_args())
                cmd.extend(["-out", priv_path])
            else:
                flash("Invalid key type.", "error")
                os.unlink(priv_path)
                return redirect(url_for("keys.generate_key"))

            subprocess.run(cmd, check=True, capture_output=True, text=True)

        except subprocess.CalledProcessError as e:
            os.unlink(priv_path)
            flash(f"Error generating key: {e.stderr}", "error")
            return redirect(url_for("keys.generate_key"))

        # extract public key
        pub_f = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        pub_path = pub_f.name
        pub_f.close()

        try:
            pub_cmd = ["openssl", "pkey", "-in", priv_path, "-pubout"]
            # Add provider args if available (needed for PQC keys)
            pub_cmd.extend(get_provider_args())
            pub_cmd.extend(["-out", pub_path])
            subprocess.run(pub_cmd, check=True, capture_output=True, text=True)

        except subprocess.CalledProcessError as e:
            os.unlink(priv_path); os.unlink(pub_path)
            flash(f"Error extracting public key: {e.stderr}", "error")
            return redirect(url_for("keys.generate_key"))

        # read keys
        with open(priv_path) as f: priv_data = f.read()
        with open(pub_path ) as f: pub_data  = f.read()
        os.unlink(priv_path); os.unlink(pub_path)


        # save to DB
        new_key = Key(
            name=key_name,
            key_type=key_type,
            key_size=int(key_size) if key_type == "RSA" else None,
            curve_name=curve_name if key_type == "EC" else None,
            pqc_alg=pqc_alg if key_type == "PQC" else None,
            private_key=priv_data,
            public_key=pub_data,
            created_at=datetime.utcnow(),
            user_id=current_user.id
        )
        db.session.add(new_key)
        db.session.commit()
        # Event logging
        try:
            from events import log_event
            log_event(
                event_type="create",
                resource_type="key",
                resource_name=key_name,
                user_id=current_user.id,
                details={"key_type": key_type}
            )
        except Exception:
            pass
        flash("Key generated successfully.", "success")
        return redirect(url_for("keys.list_keys"))

    return render_template(
        "generate_key.html",
        pqc_available=pqc_available,
        pqc_enabled=pqc_enabled,
        pqc_algorithms=PQC_ALGORITHM_CHOICES,
    )

def generate_keyX():
    if request.method == "POST":
        key_name = request.form.get("key_name")
        if not key_name:
            flash("Key name is required.", "error")
            return redirect(url_for("keys.generate_key"))
        key_type = request.form.get("key_type")
        key_size = None
        curve_name = None
        private_key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        private_key_filename = private_key_file.name
        private_key_file.close()
        try:
            if key_type == "RSA":
                key_size = request.form.get("key_size", "2048")
                rsa_cmd = ["openssl", "genrsa", "-out", private_key_filename, key_size]
                subprocess.run(rsa_cmd, check=True, capture_output=True, text=True)
            elif key_type == "EC":
                curve_name = request.form.get("curve", "prime256v1")
                ec_cmd = ["openssl", "ecparam", "-name", curve_name, "-genkey", "-noout", "-out", private_key_filename]
                subprocess.run(ec_cmd, check=True, capture_output=True, text=True)
            else:
                flash("Invalid key type selected.", "error")
                os.unlink(private_key_filename)
                return redirect(url_for("keys.generate_key"))
        except subprocess.CalledProcessError as e:
            os.unlink(private_key_filename)
            flash(f"Error generating key: {e.stderr}", "error")
            return redirect(url_for("keys.generate_key"))
        public_key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        public_key_filename = public_key_file.name
        public_key_file.close()
        try:
            if key_type == "RSA":
                pub_cmd = ["openssl", "rsa", "-in", private_key_filename, "-pubout", "-out", public_key_filename]
            elif key_type == "EC":
                pub_cmd = ["openssl", "ec", "-in", private_key_filename, "-pubout", "-out", public_key_filename]
            subprocess.run(pub_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            os.unlink(private_key_filename)
            os.unlink(public_key_filename)
            flash(f"Error extracting public key: {e.stderr}", "error")
            return redirect(url_for("keys.generate_key"))
        with open(private_key_filename, "r") as f:
            private_key_data = f.read()
        with open(public_key_filename, "r") as f:
            public_key_data = f.read()
        os.unlink(private_key_filename)
        os.unlink(public_key_filename)
        new_key = Key(
            name=key_name,
            key_type=key_type,
            key_size=int(key_size) if key_type == "RSA" else None,
            curve_name=curve_name if key_type == "EC" else None,
            private_key=private_key_data,
            public_key=public_key_data,
            created_at=datetime.utcnow()
        )
        db.session.add(new_key)
        db.session.commit()
        flash("Key generated successfully.", "success")
        return redirect(url_for("keys.list_keys"))
    return render_template("generate_key.html")

#@x509_keys_bp.route("/keys", methods=["GET"])
#def list_keys():
#    keys = Key.query.order_by(Key.created_at.desc()).all()
#    return render_template("list_keys.html", keys=keys)


from zoneinfo import ZoneInfo

def check_key_supported(key_obj):
    """Check if a key can be processed. Returns (is_supported, error_message)"""
    if normalize_key_type(key_obj.key_type) == "PQC":
        from openssl_utils import check_oqsprovider_available
        if not check_oqsprovider_available():
            return False, "Unsupported (requires oqsprovider)"
    return True, None

def build_key_formats(key_obj):
    formats = {
        "pkcs1_private": None,
        "sec1_private": None,
        "rfc4716_public": None,
        "rfc4716_public_bare": None,
        "errors": {}
    }

    def restrict_private_key(path):
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return
        username = os.environ.get("USERNAME") or getpass.getuser()
        try:
            subprocess.run(
                [
                    "icacls",
                    path,
                    "/inheritance:r",
                    "/grant:r",
                    f"{username}:(R)"
                ],
                check=True,
                capture_output=True,
                text=True
            )
            subprocess.run(
                [
                    "icacls",
                    path,
                    "/remove:g",
                    "Users",
                    "Authenticated Users",
                    "Everyone",
                    "OWNER RIGHTS"
                ],
                check=True,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError:
            pass

    with tempfile.TemporaryDirectory() as tmpdir:
        priv_path = os.path.join(tmpdir, "key.pem")
        pub_path = os.path.join(tmpdir, "key_pub.pem")
        with open(priv_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(key_obj.private_key)
        with open(pub_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(key_obj.public_key)
        restrict_private_key(priv_path)

        normalized_key_type = normalize_key_type(key_obj.key_type)

        if normalized_key_type == "RSA":
            pkcs1_path = os.path.join(tmpdir, "key_pkcs1.pem")
            pkcs1_cmd = ["openssl", "rsa", "-in", priv_path, "-traditional"]
            pkcs1_cmd.extend(get_provider_args())
            pkcs1_cmd.extend(["-out", pkcs1_path])
            try:
                subprocess.run(pkcs1_cmd, check=True, capture_output=True, text=True)
                with open(pkcs1_path, "r", encoding="utf-8") as f:
                    formats["pkcs1_private"] = f.read()
            except subprocess.CalledProcessError as e:
                formats["errors"]["pkcs1_private"] = (e.stderr or "OpenSSL failed").strip()
        elif normalized_key_type == "EC":
            sec1_path = os.path.join(tmpdir, "key_sec1.pem")
            sec1_cmd = ["openssl", "ec", "-in", priv_path]
            sec1_cmd.extend(get_provider_args())
            sec1_cmd.extend(["-out", sec1_path])
            try:
                subprocess.run(sec1_cmd, check=True, capture_output=True, text=True)
                with open(sec1_path, "r", encoding="utf-8") as f:
                    formats["sec1_private"] = f.read()
            except subprocess.CalledProcessError as e:
                formats["errors"]["sec1_private"] = (e.stderr or "OpenSSL failed").strip()

        if normalized_key_type not in ("RSA", "EC"):
            formats["errors"]["rfc4716_public"] = "RFC4716 is only supported for RSA/EC keys."
        elif not shutil.which("ssh-keygen"):
            formats["errors"]["rfc4716_public"] = "ssh-keygen is not available on PATH."
        else:
            try:
                openssh_pub = subprocess.run(
                    ["ssh-keygen", "-y", "-f", priv_path],
                    check=True,
                    capture_output=True,
                    text=True
                ).stdout
                openssh_path = os.path.join(tmpdir, "key_openssh.pub")
                with open(openssh_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(openssh_pub)
                rfc4716_pub = subprocess.run(
                    ["ssh-keygen", "-e", "-m", "RFC4716", "-f", openssh_path],
                    check=True,
                    capture_output=True,
                    text=True
                ).stdout
                formats["rfc4716_public"] = rfc4716_pub
                openssh_line = openssh_pub.strip()
                formats["rfc4716_public_bare"] = f"{openssh_line}\n" if openssh_line else None
            except subprocess.CalledProcessError as e:
                err = (e.stderr or e.stdout or "ssh-keygen failed").strip()
                formats["errors"]["rfc4716_public"] = err

    return formats

@x509_keys_bp.route("/keys", methods=["GET"])
@login_required
def list_keys():
    if current_user.is_admin():
        keys = Key.query.order_by(Key.created_at.desc()).all()
        # Fetch user info for each key
        from user_models import get_user_by_id
        for k in keys:
            k.user_obj = get_user_by_id(k.user_id) if k.user_id else None
    else:
        keys = Key.query.filter_by(user_id=current_user.id).order_by(Key.created_at.desc()).all()
        for k in keys:
            k.user_obj = current_user

    # convert each key’s created_at to the system tz (or hardcode Asia/Jerusalem)
    local_keys = []
    for k in keys:
        dt = k.created_at
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo("UTC"))
            dt_local = dt.astimezone()
            k.created_at_local = dt_local
        else:
            k.created_at_local = None
        is_supported, error_msg = check_key_supported(k)
        k.is_supported = is_supported
        k.support_error = error_msg
        k.pqc_alg_display = derive_pqc_label_from_key(k)
        local_keys.append(k)
    return render_template("list_keys.html", keys=local_keys, is_admin=current_user.is_admin())


@x509_keys_bp.route("/keys/state", methods=["GET"])
@login_required
def keys_state():
    admin = current_user.is_authenticated and (current_user.is_admin() if callable(getattr(current_user, "is_admin", None)) else getattr(current_user, "is_admin", False))
    query = Key.query
    if not admin:
        query = query.filter_by(user_id=current_user.id)
    count = query.count()
    max_id_row = query.order_by(Key.id.desc()).with_entities(Key.id).first()
    max_id = max_id_row[0] if max_id_row else 0
    return jsonify({"count": count, "max_id": max_id})


@x509_keys_bp.route("/keys/<int:key_id>", methods=["GET"])
@login_required
def view_key(key_id):
    if current_user.is_admin():
        key_obj = Key.query.get_or_404(key_id)
    else:
        key_obj = Key.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    key_formats = build_key_formats(key_obj)
    key_obj.pqc_alg_display = get_pqc_algorithm_label(key_obj.pqc_alg) if key_obj.key_type == "PQC" else None
    return render_template(
        "view_key.html",
        key=key_obj,
        pkcs1_private=key_formats["pkcs1_private"],
        sec1_private=key_formats["sec1_private"],
        rfc4716_public=key_formats["rfc4716_public"],
        rfc4716_public_bare=key_formats["rfc4716_public_bare"],
        format_errors=key_formats["errors"]
    )


@x509_keys_bp.route("/keys/<int:key_id>/download", methods=["GET"])
@login_required
def download_key(key_id):
    if current_user.is_admin():
        key_obj = Key.query.get_or_404(key_id)
    else:
        key_obj = Key.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    pem_bytes = key_obj.private_key.encode("utf-8")
    buf = io.BytesIO(pem_bytes)
    buf.seek(0)
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"{key_obj.name}.pem",
        mimetype="application/x-pem-file"
    )


@x509_keys_bp.route("/api/keys/<path:key_name>/private", methods=["GET"])
def api_get_private_key_by_name(key_name):
    key_obj, token_info_or_response = _lookup_key_for_token(key_name)
    if key_obj is None:
        return token_info_or_response
    try:
        from events import log_event
        log_event(
            event_type="read",
            resource_type="key_private",
            resource_name=key_obj.name,
            user_id=token_info_or_response["user_id"],
            details={"via": "api_token", "key_id": key_obj.id},
        )
    except Exception:
        pass
    return _api_key_response(key_obj.private_key, key_obj, "private")


@x509_keys_bp.route("/api/keys/<path:key_name>/public", methods=["GET"])
def api_get_public_key_by_name(key_name):
    key_obj, token_info_or_response = _lookup_key_for_token(key_name)
    if key_obj is None:
        return token_info_or_response
    try:
        from events import log_event
        log_event(
            event_type="read",
            resource_type="key_public",
            resource_name=key_obj.name,
            user_id=token_info_or_response["user_id"],
            details={"via": "api_token", "key_id": key_obj.id},
        )
    except Exception:
        pass
    return _api_key_response(key_obj.public_key, key_obj, "public")



@x509_keys_bp.route("/keys/<int:key_id>/delete", methods=["POST"])
@login_required
def delete_key(key_id):
    if current_user.is_admin():
        key_obj = Key.query.get_or_404(key_id)
    else:
        key_obj = Key.query.filter_by(id=key_id, user_id=current_user.id).first_or_404()
    db.session.delete(key_obj)
    db.session.commit()
    # Event logging
    try:
        from events import log_event
        log_event(
            event_type="delete",
            resource_type="key",
            resource_name=key_obj.name,
            user_id=current_user.id,
            details={}
        )
    except Exception:
        pass
    flash("Key deleted successfully.", "success")
    return redirect(url_for("keys.list_keys"))

