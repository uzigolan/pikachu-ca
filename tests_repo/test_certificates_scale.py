import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask_login.utils import _create_identifier

from app import _build_certificate_listing_cache
from user_models import create_user_db, get_user_by_username


def _ensure_admin(app):
    with app.app_context():
        admin = get_user_by_username("admin")
        if admin is None:
            create_user_db("admin", "pikachu", role="admin", status="active")


def _force_login_admin(client, app):
    with app.app_context():
        admin = get_user_by_username("admin")
        assert admin is not None
    with client.application.test_request_context("/", headers={"User-Agent": "pytest-scale-client"}):
        session_id = _create_identifier()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin.id)
        sess["_fresh"] = True
        sess["_id"] = session_id
    return client.get("/certs", follow_redirects=True)


def _get_admin_id(app):
    with app.app_context():
        admin = get_user_by_username("admin")
        assert admin is not None
        return admin.id


def _build_cert_pem(common_name: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKISquire Scale Tests"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _cleanup_scale_rows(app, subject_prefix: str):
    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.execute("DELETE FROM certificates WHERE subject LIKE ?", (f"%{subject_prefix}%",))
        conn.commit()


@pytest.mark.usefixtures("app", "client")
def test_certs_listing_scale_is_paginated_and_fast(client, app):
    _ensure_admin(app)
    _force_login_admin(client, app)
    admin_id = _get_admin_id(app)

    subject_prefix = "scale-cert-"
    _cleanup_scale_rows(app, subject_prefix)

    rows = []
    for idx in range(220):
        common_name = f"{subject_prefix}{idx:03d}"
        cert_pem = _build_cert_pem(common_name)
        cache = _build_certificate_listing_cache(cert_pem)
        rows.append((
            f"commonName={common_name}, organizationName=PKISquire Scale Tests",
            f"0xscale{idx:03d}",
            cert_pem,
            admin_id,
            "ui",
            cache["common_name"],
            cache["keycol"],
            cache["not_valid_before"],
            cache["not_valid_after"],
        ))

    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            conn.executemany(
                """
                INSERT INTO certificates (
                    subject, serial, cert_pem, user_id, issued_via,
                    common_name, keycol, not_valid_before, not_valid_after
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()

        start = time.perf_counter()
        response = client.get("/certs?page=1&page_size=25&q=scale-cert-", follow_redirects=True)
        duration = time.perf_counter() - start

        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert "scale-cert-219" in body
        assert "scale-cert-195" in body
        assert "scale-cert-194" not in body
        assert "Page 1 / 9 (220 total)" in body
        assert duration < 3.0, f"/certs took too long with 220 rows: {duration:.2f}s"
    finally:
        _cleanup_scale_rows(app, subject_prefix)


@pytest.mark.usefixtures("app", "client")
def test_certs_listing_backfills_missing_cache_columns(client, app):
    _ensure_admin(app)
    _force_login_admin(client, app)
    admin_id = _get_admin_id(app)

    subject_prefix = "scale-backfill-"
    _cleanup_scale_rows(app, subject_prefix)

    common_name = f"{subject_prefix}001"
    cert_pem = _build_cert_pem(common_name)

    try:
        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            conn.execute(
                """
                INSERT INTO certificates (
                    subject, serial, cert_pem, user_id, issued_via,
                    common_name, keycol, not_valid_before, not_valid_after
                ) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)
                """,
                (
                    f"commonName={common_name}, organizationName=PKISquire Scale Tests",
                    "0xbackfill001",
                    cert_pem,
                    admin_id,
                    "ui",
                ),
            )
            conn.commit()

        response = client.get("/certs?page=1&page_size=10&q=scale-backfill-", follow_redirects=True)
        assert response.status_code == 200

        with sqlite3.connect(app.config["DB_PATH"]) as conn:
            row = conn.execute(
                """
                SELECT common_name, keycol, not_valid_before, not_valid_after
                FROM certificates
                WHERE serial = ?
                """,
                ("0xbackfill001",),
            ).fetchone()
        assert row is not None
        assert row[0] == common_name
        assert row[1]
        assert row[2]
        assert row[3]
    finally:
        _cleanup_scale_rows(app, subject_prefix)
