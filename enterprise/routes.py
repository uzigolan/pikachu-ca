import base64
import binascii
import datetime as dt
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone

from asn1crypto import ocsp as asn1_ocsp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPResponderEncoding,
    OCSPResponseBuilder,
    OCSPResponseStatus,
    load_der_ocsp_request,
)
from cryptography.x509.oid import ExtensionOID
from flask import Response, current_app, jsonify, make_response, redirect, render_template, request, session, url_for, flash
from flask_login import current_user

from enterprise.challenge_passwords import (
    CHALLENGE_MODE_CHOICES,
    CHALLENGE_MODE_REUSABLE,
    CHALLENGE_MODE_REUSABLE_UNLIMITED,
    DEFAULT_CHALLENGE_MODE,
    build_challenge_password_view,
    compute_expiry,
    normalize_challenge_mode,
    parse_validity_timedelta,
)
from enterprise.preshared_keys import (
    api_create_preshared_key,
    api_delete_preshared_key,
    api_get_preshared_key,
    api_start_preshared_key_rotation,
    api_stop_preshared_key_rotation,
    delete_preshared_key,
    preshared_keys_data,
    preshared_keys,
    preshared_keys_state,
    regenerate_preshared_key,
    revoke_preshared_key,
    toggle_preshared_key_rotation,
)


def delete_challenge_password():
    value = request.form.get("value") or request.args.get("value")
    if not value:
        flash("No challenge password specified.", "error")
        return redirect(url_for("challenge_passwords"))
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT value, user_id, consumed, created_at, validity, usage_mode, use_count, last_used_at FROM challenge_passwords WHERE value = ?",
            (value,),
        ).fetchone()
        if not row:
            flash("Challenge password not found.", "error")
            return redirect(url_for("challenge_passwords"))
        if not current_user.is_admin() and row["user_id"] != current_user.id:
            flash("You do not have permission to delete this challenge password.", "error")
            return redirect(url_for("challenge_passwords"))
        conn.execute("DELETE FROM challenge_passwords WHERE value = ?", (value,))
        conn.commit()
        try:
            from events import log_event

            log_event(
                event_type="delete",
                resource_type="challenge_password",
                resource_name=value,
                user_id=current_user.id,
                details={},
            )
        except Exception:
            pass
    flash("Challenge password deleted.", "success")
    return redirect(url_for("challenge_passwords"))


def delete_all_expired_challenge_passwords():
    now = datetime.utcnow()
    scope = request.form.get("scope") or request.args.get("scope", "own")
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if current_user.is_admin() and scope == "all":
            rows = conn.execute(
                "SELECT value, user_id, created_at, validity, consumed, usage_mode, use_count, last_used_at FROM challenge_passwords"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT value, user_id, created_at, validity, consumed, usage_mode, use_count, last_used_at FROM challenge_passwords WHERE user_id = ?",
                (current_user.id,),
            ).fetchall()
        to_delete = []
        for row in rows:
            expires_dt, expired = compute_expiry(row["created_at"], row["validity"], row["usage_mode"])
            if expired and expires_dt and now.replace(tzinfo=timezone.utc) > expires_dt:
                to_delete.append(row["value"])
        if to_delete:
            conn.executemany("DELETE FROM challenge_passwords WHERE value = ?", [(v,) for v in to_delete])
            conn.commit()
            try:
                from events import log_event

                log_event(
                    event_type="bulk_delete",
                    resource_type="challenge_password",
                    resource_name="bulk",
                    user_id=current_user.id,
                    details={"count": len(to_delete)},
                )
            except Exception:
                pass
            flash(f"Deleted {len(to_delete)} expired challenge passwords.", "success")
        else:
            flash("No expired challenge passwords to delete.", "info")
    return redirect(url_for("challenge_passwords"))


def challenge_passwords_data():
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if current_user.is_admin():
            rows = conn.execute(
                "SELECT value, user_id, created_at, validity, consumed, usage_mode, use_count, last_used_at FROM challenge_passwords ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT value, user_id, created_at, validity, consumed, usage_mode, use_count, last_used_at FROM challenge_passwords WHERE user_id = ? ORDER BY created_at DESC",
                (current_user.id,),
            ).fetchall()
    from user_models import get_username_by_id

    result = []
    for row in rows:
        result.append(build_challenge_password_view(row, get_username_by_id(row["user_id"]) if row["user_id"] else ""))
    return jsonify(result)


def api_create_challenge_password(verify_api_token):
    raw_token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        raw_token = auth_header.split(" ", 1)[1].strip()
    raw_token = raw_token or request.headers.get("X-API-Token") or request.args.get("token") or (
        request.json.get("token") if request.is_json else None
    )
    if not raw_token:
        return jsonify({"error": "API token required"}), 401
    token_info = verify_api_token(raw_token)
    if not token_info:
        return jsonify({"error": "Invalid or expired API token"}), 401
    if not current_app.config.get("SCEP_CHALLENGE_PASSWORD_ENABLED", False):
        return jsonify({"error": "Challenge password feature is disabled"}), 400

    payload = request.get_json(silent=True) or {}
    usage_mode = normalize_challenge_mode(
        payload.get("usage_mode") or request.form.get("usage_mode") or request.args.get("usage_mode")
    )
    default_validity = current_app.config.get("SCEP_CHALLENGE_PASSWORD_VALIDITY", "60m").strip()
    requested_validity = (
        payload.get("validity") or request.form.get("validity") or request.args.get("validity") or default_validity
    )
    if usage_mode == CHALLENGE_MODE_REUSABLE_UNLIMITED:
        delta = None
        validity_str = None
    else:
        delta, validity_str = parse_validity_timedelta(str(requested_validity).strip())
    now = datetime.now(timezone.utc)
    value = secrets.token_bytes(16).hex().upper()
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute(
            """
            INSERT INTO challenge_passwords
            (value, user_id, created_at, validity, consumed, usage_mode, use_count, last_used_at)
            VALUES (?, ?, ?, ?, 0, ?, 0, NULL)
            """,
            (value, token_info["user_id"], now.strftime("%Y-%m-%d %H:%M:%S UTC"), validity_str, usage_mode),
        )
        conn.commit()
    expires_at = (now + delta).strftime("%Y-%m-%d %H:%M:%S UTC") if delta else None
    try:
        from events import log_event

        log_event(
            event_type="create",
            resource_type="challenge_password",
            resource_name=value,
            user_id=token_info["user_id"],
            details={"validity": validity_str, "usage_mode": usage_mode, "via": "api_token"},
        )
    except Exception:
        pass
    return (
        jsonify(
            {
                "value": value,
                "user_id": token_info["user_id"],
                "validity": validity_str or "Unlimited",
                "usage_mode": usage_mode,
                "use_count": 0,
                "created_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "expires_at": expires_at,
            }
        ),
        201,
    )


def challenge_passwords():
    default_validity = current_app.config.get("SCEP_CHALLENGE_PASSWORD_VALIDITY", "60m").strip()
    if request.method == "POST":
        usage_mode = normalize_challenge_mode(request.form.get("usage_mode") or DEFAULT_CHALLENGE_MODE)
        requested_validity = (request.form.get("validity") or default_validity).strip()
        if usage_mode == CHALLENGE_MODE_REUSABLE_UNLIMITED:
            delta = None
            validity_str = None
        else:
            delta, validity_str = parse_validity_timedelta(requested_validity)
        now = datetime.now(timezone.utc)
        value = secrets.token_bytes(16).hex().upper()
        with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
            conn.execute(
                """
                INSERT INTO challenge_passwords
                (value, user_id, created_at, validity, consumed, usage_mode, use_count, last_used_at)
                VALUES (?, ?, ?, ?, 0, ?, 0, NULL)
                """,
                (value, current_user.id, now.strftime("%Y-%m-%d %H:%M:%S UTC"), validity_str, usage_mode),
            )
            conn.commit()
        try:
            from events import log_event

            log_event(
                event_type="create",
                resource_type="challenge_password",
                resource_name=value,
                user_id=current_user.id,
                details={"validity": validity_str, "usage_mode": usage_mode},
            )
        except Exception:
            pass
        session["generated_challenge_password"] = {
            "value": value,
            "user": current_user.username,
            "created_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "validity": validity_str or "Unlimited",
            "usage_mode": usage_mode,
            "usage_mode_label": "Reusable Unlimited" if usage_mode == CHALLENGE_MODE_REUSABLE_UNLIMITED else ("Reusable" if usage_mode == CHALLENGE_MODE_REUSABLE else "Single Use"),
            "use_count": 0,
            "consumed": False,
            "expires_at": (now + delta).strftime("%Y-%m-%d %H:%M:%S UTC") if delta else None,
        }
        return redirect(url_for("challenge_passwords"))
    generated = session.pop("generated_challenge_password", None)
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.row_factory = sqlite3.Row
        if current_user.is_admin():
            rows = conn.execute(
                "SELECT value, user_id, created_at, validity, consumed, usage_mode, use_count, last_used_at FROM challenge_passwords ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT value, user_id, created_at, validity, consumed, usage_mode, use_count, last_used_at FROM challenge_passwords WHERE user_id = ? ORDER BY created_at DESC",
                (current_user.id,),
            ).fetchall()
    from user_models import get_username_by_id

    challenge_passwords = [
        build_challenge_password_view(row, get_username_by_id(row["user_id"]) if row["user_id"] else "")
        for row in rows
    ]
    return render_template(
        "challenge_passwords.html",
        generated=generated,
        challenge_passwords=challenge_passwords,
        is_admin=current_user.is_admin(),
        challenge_mode_choices=CHALLENGE_MODE_CHOICES,
        default_validity=default_validity,
    )


def _ocsp_hash_algorithm():
    if current_app.config.get("OCSP_HASH_ALGORITHM") == "sha256":
        return hashes.SHA256()
    return hashes.SHA1()  # nosec B303 - legacy OCSP client compatibility


def ocspv():
    try:
        if request.method == "GET":
            b64_req = request.args.get("ocsp")
            if not b64_req:
                raise ValueError("No OCSP request found in query param")
            request_data = base64.b64decode(b64_req)
        else:
            request_data = request.data
            if not request_data:
                raise ValueError("Empty OCSP request body")
        ocsp_req = load_der_ocsp_request(request_data)
        requests_serials = [ocsp_req.serial_number]
        try:
            asn1_req = asn1_ocsp.OCSPRequest.load(request_data)
            req_list = asn1_req["tbs_request"]["request_list"]
            if len(req_list) > 1:
                requests_serials = [single["req_cert"]["serial_number"].native for single in req_list]
        except Exception:
            pass
        with open(current_app.config["SUBCA_CERT_PATH"], "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(current_app.config["SUBCA_KEY_PATH"], "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        now = dt.datetime.utcnow()
        next_update = now + dt.timedelta(days=7)
        builder = OCSPResponseBuilder()
        with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
            for sn in requests_serials:
                row = conn.execute("SELECT cert_pem, revoked FROM certificates WHERE serial = ?", (hex(sn),)).fetchone()
                if not row:
                    ocsp_resp = OCSPResponseBuilder.build_unsuccessful(OCSPResponseStatus.UNAUTHORIZED)
                    return make_response(
                        ocsp_resp.public_bytes(serialization.Encoding.DER),
                        200,
                        {"Content-Type": "application/ocsp-response"},
                    )
                cert_pem, revoked_flag = row
                target_cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                revoked = revoked_flag == 1
                builder = builder.add_response(
                    cert=target_cert,
                    issuer=ca_cert,
                    algorithm=_ocsp_hash_algorithm(),
                    cert_status=OCSPCertStatus.REVOKED if revoked else OCSPCertStatus.GOOD,
                    this_update=now,
                    next_update=next_update,
                    revocation_time=now if revoked else None,
                    revocation_reason=x509.ReasonFlags.unspecified if revoked else None,
                )
        builder = builder.responder_id(OCSPResponderEncoding.HASH, ca_cert)
        try:
            for ext in ocsp_req.extensions:
                if ext.oid == ExtensionOID.OCSP_NONCE:
                    builder = builder.add_extension(ext, critical=False)
                    break
        except Exception:
            pass
        ocsp_response = builder.sign(private_key, hashes.SHA256())
        return make_response(
            ocsp_response.public_bytes(serialization.Encoding.DER),
            200,
            {"Content-Type": "application/ocsp-response"},
        )
    except Exception as e:
        current_app.logger.error(f"OCSP request processing failed: {str(e)}")
        return f"OCSP request processing failed: {str(e)}", 400


def ocsp():
    try:
        if request.method == "GET":
            b64_req = request.args.get("ocsp")
            if not b64_req:
                raise ValueError("No OCSP request found in query param")
            request_data = base64.b64decode(b64_req)
        else:
            request_data = request.data
            if not request_data:
                raise ValueError("Empty OCSP request body")
        asn1_req = asn1_ocsp.OCSPRequest.load(request_data)
        req_list = asn1_req["tbs_request"]["request_list"]
        with open(current_app.config["SUBCA_CERT_PATH"], "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(current_app.config["SUBCA_KEY_PATH"], "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        now = dt.datetime.utcnow()
        next_update = now + dt.timedelta(days=7)
        builder = OCSPResponseBuilder()
        with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
            for single_req in req_list:
                req_cert = single_req["req_cert"]
                serial_number = req_cert["serial_number"].native
                row = conn.execute(
                    "SELECT cert_pem, revoked FROM certificates WHERE serial = ?",
                    (hex(serial_number),),
                ).fetchone()
                if not row:
                    ocsp_resp = OCSPResponseBuilder.build_unsuccessful(OCSPResponseStatus.UNAUTHORIZED)
                    return make_response(
                        ocsp_resp.public_bytes(serialization.Encoding.DER),
                        200,
                        {"Content-Type": "application/ocsp-response"},
                    )
                cert_pem, revoked_flag = row
                target_cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
                revoked = revoked_flag == 1
                builder = builder.add_response(
                    cert=target_cert,
                    issuer=ca_cert,
                    algorithm=_ocsp_hash_algorithm(),
                    cert_status=OCSPCertStatus.REVOKED if revoked else OCSPCertStatus.GOOD,
                    this_update=now,
                    next_update=next_update,
                    revocation_time=now if revoked else None,
                    revocation_reason=x509.ReasonFlags.unspecified if revoked else None,
                )
        builder = builder.responder_id(OCSPResponderEncoding.HASH, ca_cert)
        req_exts = asn1_req["tbs_request"]["request_extensions"]
        if req_exts is not None:
            for ext in req_exts:
                if ext["extn_id"].native == "ocsp_nonce":
                    nonce_bytes = ext["extn_value"].native
                    builder = builder.add_extension(
                        x509.UnrecognizedExtension(
                            x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.2"),
                            nonce_bytes,
                        ),
                        critical=False,
                    )
        ocsp_response = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
        return make_response(
            ocsp_response.public_bytes(serialization.Encoding.DER),
            200,
            {"Content-Type": "application/ocsp-response"},
        )
    except Exception as e:
        current_app.logger.error(f"OCSP request processing failed: {str(e)}")
        return f"OCSP request processing failed: {str(e)}", 400


def est_cacerts():
    with tempfile.NamedTemporaryFile(suffix=".p7", delete=False) as tmp:
        p7_path = tmp.name
    subprocess.run(
        [
            "openssl",
            "crl2pkcs7",
            "-nocrl",
            "-certfile",
            current_app.config["CHAIN_FILE_PATH"],
            "-outform",
            "DER",
            "-out",
            p7_path,
        ],
        check=True,
    )
    der = open(p7_path, "rb").read()
    b64 = base64.encodebytes(der).decode("ascii")
    headers = {
        "Content-Type": "application/pkcs7-mime; smime-type=certs",
        "Content-Transfer-Encoding": "base64",
        "Content-Disposition": 'attachment; filename="cacerts.p7"',
    }
    return Response(b64, headers=headers, status=200)


def est_enroll(normalize_to_der, get_ca_instance, resolve_ra_policy, default_validity_days):
    raw = request.get_data()
    ext_block = request.form.get("ext_block", "v3_ext")
    mgr, policy = resolve_ra_policy(None, None)
    try:
        der_csr = normalize_to_der(raw)
        pem_csr = (
            b"-----BEGIN CERTIFICATE REQUEST-----\n"
            + base64.encodebytes(der_csr)
            + b"-----END CERTIFICATE REQUEST-----\n"
        )
        csr_obj = x509.load_pem_x509_csr(pem_csr, default_backend())
    except Exception as e:
        current_app.logger.error(f"Invalid CSR encoding: {e}")
        return "Invalid CSR encoding", 400
    validity_days = mgr.get_validity_days(policy)
    try:
        validity_int = int(str(validity_days))
    except Exception:
        validity_int = int(default_validity_days)

    ca = get_ca_instance()
    vault_mode = getattr(ca, "_vault_enabled", False)
    if vault_mode:
        try:
            cert = ca.sign(csr_obj, ttl=validity_int)
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        except Exception as e:
            current_app.logger.error(f"EST: Vault CA signing failed: {e}")
            return f"Vault CA signing failed: {e}", 500
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
            csr_file.write(der_csr)
            csr_der_filename = csr_file.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_file:
            cert_filename = cert_file.name
        custom_serial_str = hex(secrets.randbits(64))
        with mgr.temp_extfile(policy) as extfile_path:
            if not extfile_path:
                return "No extension config available", 400
            cmd = [
                "openssl",
                "x509",
                "-req",
                "-inform",
                "DER",
                "-in",
                str(csr_der_filename),
                "-CA",
                str(current_app.config["SUBCA_CERT_PATH"]),
                "-CAkey",
                str(current_app.config["SUBCA_KEY_PATH"]),
                "-set_serial",
                str(custom_serial_str),
                "-days",
                str(validity_int),
                "-out",
                str(cert_filename),
                "-extfile",
                str(extfile_path),
                "-extensions",
                str(ext_block),
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        with open(cert_filename, "r") as f:
            cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        try:
            os.unlink(csr_der_filename)
            os.unlink(cert_filename)
        except Exception:
            pass

    subject_str = ", ".join(f"{attr.oid._name}={attr.value}" for attr in cert.subject)
    actual_serial = hex(cert.serial_number)
    user_id = current_user.id if current_user.is_authenticated else None
    with sqlite3.connect(current_app.config["DB_PATH"]) as conn:
        conn.execute(
            "INSERT INTO certificates (subject, serial, cert_pem, user_id, issued_via) VALUES (?, ?, ?, ?, ?)",
            (subject_str, actual_serial, cert_pem, user_id, "est"),
        )
    try:
        from events import log_event

        log_event(
            event_type="create",
            resource_type="certificate",
            resource_name=actual_serial,
            user_id=user_id if user_id is not None else "est",
            details={"subject": subject_str},
        )
    except Exception:
        pass
    signed_cert_path = os.path.join("pki-misc", "est_signed_cert.pem")
    with open(signed_cert_path, "wb") as f:
        f.write(cert_pem.encode())
    pkcs7_path = os.path.join("pki-misc", "est_cert_chain.p7")
    subprocess.run(
        [
            "openssl",
            "crl2pkcs7",
            "-nocrl",
            "-certfile",
            signed_cert_path,
            "-outform",
            "DER",
            "-out",
            pkcs7_path,
        ],
        check=True,
    )
    pkcs7_der = open(pkcs7_path, "rb").read()
    b64 = base64.encodebytes(pkcs7_der)
    resp = make_response(b64, 200)
    resp.headers["Content-Type"] = "application/pkcs7-mime; smime-type=signed-data"
    resp.headers["Content-Transfer-Encoding"] = "base64"
    resp.headers["Content-Disposition"] = 'attachment; filename="enroll.p7"'
    return resp
