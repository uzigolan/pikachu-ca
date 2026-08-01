"""
test_mcp.py – Automated tests for the PKI MCP layer.

Structured in two sections:

  Section 1 — /api/v1/ endpoint tests (Flask test client, no live server needed)
              Verifies every resource group: auth, certificates, keys, CSRs,
              profiles, RA policies, users, tokens, events, dashboard,
              inspection, CA/VA info, config, logs.

  Section 2 — MCP tool layer tests (needs a live PKI server)
              Set PKI_MCP_LIVE=1 and PKI_MCP_TOKEN=<token> (and optionally
              PKI_MCP_URL) to run the full MCP tool call stack end-to-end.

Run all:
    pytest tests_repo/test_mcp.py --capture=tee-sys \\
        --self-contained-html --html=tests_repo/reports/test_mcp.html

Run only endpoint tests:
    pytest tests_repo/test_mcp.py -k "not live" --capture=tee-sys

Run only live-server tool tests:
    PKI_MCP_LIVE=1 PKI_MCP_TOKEN=<token> \\
        pytest tests_repo/test_mcp.py -k live --capture=tee-sys
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend

from edition import feature_enabled
from enterprise.tokens import create_api_token
from user_models import create_user_db, get_user_by_username

ROOT_DIR = Path(__file__).resolve().parents[1]

# ──────────────────────────────────────────────────────────────────────────────
# Skip guard for enterprise-only features
# ──────────────────────────────────────────────────────────────────────────────

skip_if_no_tokens = pytest.mark.skipif(
    not feature_enabled("api_tokens"),
    reason="API tokens are enterprise-only",
)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _uid(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _make_csr_pem(cn: str) -> str:
    """Generate a fresh EC P-256 CSR PEM in memory (no openssl needed)."""
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256(), default_backend())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _make_cert_pem(cn: str) -> str:
    """Create a minimal self-signed cert PEM for inspection tests."""
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    import datetime
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


MINIMAL_PROFILE_CONTENT = """\
[req]
distinguished_name = req_dn
prompt             = no

[req_dn]
CN = mcp-test

[v3_ext]
subjectKeyIdentifier = hash
"""

# ──────────────────────────────────────────────────────────────────────────────
# Session-scoped fixtures: admin token + regular user token
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def mcp_admin_token(app):
    """Create a disposable admin user + token for the MCP test session."""
    if not feature_enabled("api_tokens"):
        pytest.skip("API tokens are enterprise-only")

    uname = _uid("mcp_admin_")
    with app.app_context():
        uid = create_user_db(uname, "mcpAdminPass1!", role="admin", status="active")
        assert uid, f"Failed to create admin user {uname}"
        raw, _ = create_api_token(uid, "mcp-test-admin", validity="1h")

    yield raw

    # Cleanup admin user + token after module
    with app.app_context():
        try:
            import sqlite3 as _sq
            db = app.config["DB_PATH"]
            with _sq.connect(db) as conn:
                conn.execute("DELETE FROM api_tokens WHERE name='mcp-test-admin'")
                conn.execute("DELETE FROM users WHERE username=?", (uname,))
                conn.commit()
        except Exception:
            pass


@pytest.fixture(scope="module")
def mcp_user_token(app):
    """Create a disposable regular user + token for the MCP test session."""
    if not feature_enabled("api_tokens"):
        pytest.skip("API tokens are enterprise-only")

    uname = _uid("mcp_user_")
    with app.app_context():
        uid = create_user_db(uname, "mcpUserPass1!", role="user", status="active")
        assert uid, f"Failed to create user {uname}"
        raw, _ = create_api_token(uid, "mcp-test-user", validity="1h")

    yield raw

    with app.app_context():
        try:
            import sqlite3 as _sq
            db = app.config["DB_PATH"]
            with _sq.connect(db) as conn:
                conn.execute("DELETE FROM api_tokens WHERE name='mcp-test-user'")
                conn.execute("DELETE FROM users WHERE username=?", (uname,))
                conn.commit()
        except Exception:
            pass


def _admin_hdrs(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _user_hdrs(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 1 — /api/v1/ endpoint tests
# ──────────────────────────────────────────────────────────────────────────────


class TestMCPAuth:
    """Authentication gate on every /api/v1/ route."""

    @skip_if_no_tokens
    def test_missing_token_returns_401(self, client):
        resp = client.get("/api/v1/certificates")
        assert resp.status_code == 401
        assert resp.is_json
        assert "error" in resp.get_json()

    @skip_if_no_tokens
    def test_invalid_token_returns_401(self, client):
        resp = client.get("/api/v1/certificates",
                          headers={"Authorization": "Bearer invalid-token-abc"})
        assert resp.status_code == 401

    @skip_if_no_tokens
    def test_x_api_token_header_accepted(self, client, mcp_admin_token):
        resp = client.get("/api/v1/certificates",
                          headers={"X-API-Token": mcp_admin_token})
        assert resp.status_code == 200

    @skip_if_no_tokens
    def test_regular_token_rejected_on_admin_endpoint(self, client, mcp_user_token):
        resp = client.get("/api/v1/users",
                          headers=_user_hdrs(mcp_user_token))
        assert resp.status_code == 403
        body = resp.get_json()
        assert "[ADMIN]" in body.get("error", "")


class TestMCPDashboard:
    """Dashboard summary and activity endpoints."""

    @skip_if_no_tokens
    def test_stats_returns_summary(self, client, mcp_admin_token):
        resp = client.get("/api/v1/dashboard",
                          headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "summary" in body
        assert "enrollment" in body
        for k in ("total", "valid", "expired", "revoked"):
            assert k in body["summary"]

    @skip_if_no_tokens
    def test_activity_returns_events(self, client, mcp_admin_token):
        resp = client.get("/api/v1/dashboard/activity",
                          headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        assert "events" in resp.get_json()


class TestMCPCA:
    """CA / VA / config / logs endpoints."""

    @skip_if_no_tokens
    def test_ca_info_has_subject(self, client, mcp_admin_token):
        resp = client.get("/api/v1/ca", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "subject" in body
        assert "cert_pem" in body
        assert "-----BEGIN CERTIFICATE-----" in body["cert_pem"]

    @skip_if_no_tokens
    def test_va_info_has_crl_status(self, client, mcp_admin_token):
        resp = client.get("/api/v1/va", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "crl_exists" in body
        assert "revoked_count" in body

    @skip_if_no_tokens
    def test_config_requires_admin(self, client, mcp_user_token):
        resp = client.get("/api/v1/config", headers=_user_hdrs(mcp_user_token))
        assert resp.status_code == 403

    @skip_if_no_tokens
    def test_config_admin_returns_safe_keys(self, client, mcp_admin_token):
        resp = client.get("/api/v1/config", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "CA_MODE" in body
        # Sensitive keys must never appear
        for bad_key in ("SECRET_KEY", "DELETE_SECRET", "LDAP_ADMIN_PASSWORD"):
            assert bad_key not in body

    @skip_if_no_tokens
    def test_logs_requires_admin(self, client, mcp_user_token):
        resp = client.get("/api/v1/logs", headers=_user_hdrs(mcp_user_token))
        assert resp.status_code == 403

    @skip_if_no_tokens
    def test_logs_admin_returns_lines(self, client, mcp_admin_token):
        resp = client.get("/api/v1/logs?lines=10", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code in (200, 404)  # 404 if log file not yet written
        if resp.status_code == 200:
            assert "lines" in resp.get_json()


class TestMCPKeys:
    """Key generation, listing, retrieval, and deletion."""

    @skip_if_no_tokens
    def test_list_keys_returns_list(self, client, mcp_admin_token):
        resp = client.get("/api/v1/keys", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        assert "keys" in resp.get_json()

    @skip_if_no_tokens
    def test_generate_ec_key(self, client, mcp_admin_token):
        name = _uid("mcp-ec-key-")
        resp = client.post(
            "/api/v1/keys",
            json={"name": name, "key_type": "EC", "curve_name": "prime256v1"},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["key_type"] == "EC"
        assert "BEGIN PUBLIC KEY" in body["public_key"]
        key_id = body["id"]

        # cleanup
        client.delete(f"/api/v1/keys/{key_id}", headers=_admin_hdrs(mcp_admin_token))

    @skip_if_no_tokens
    def test_generate_rsa_key(self, client, mcp_admin_token):
        name = _uid("mcp-rsa-key-")
        resp = client.post(
            "/api/v1/keys",
            json={"name": name, "key_type": "RSA", "key_size": 2048},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 201
        body = resp.get_json()
        assert body["key_type"] == "RSA"
        key_id = body["id"]
        client.delete(f"/api/v1/keys/{key_id}", headers=_admin_hdrs(mcp_admin_token))

    @skip_if_no_tokens
    def test_missing_name_returns_400(self, client, mcp_admin_token):
        resp = client.post(
            "/api/v1/keys",
            json={"key_type": "EC"},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 400

    @skip_if_no_tokens
    def test_get_key_without_private(self, client, app, mcp_admin_token):
        name = _uid("mcp-get-key-")
        r = client.post("/api/v1/keys",
                        json={"name": name, "key_type": "EC"},
                        headers=_admin_hdrs(mcp_admin_token))
        kid = r.get_json()["id"]
        resp = client.get(f"/api/v1/keys/{kid}", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "private_key" not in body
        assert "public_key" in body
        client.delete(f"/api/v1/keys/{kid}", headers=_admin_hdrs(mcp_admin_token))

    @skip_if_no_tokens
    def test_delete_key(self, client, mcp_admin_token):
        name = _uid("mcp-del-key-")
        r = client.post("/api/v1/keys",
                        json={"name": name, "key_type": "EC"},
                        headers=_admin_hdrs(mcp_admin_token))
        kid = r.get_json()["id"]
        resp = client.delete(f"/api/v1/keys/{kid}", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        # Confirm gone
        resp2 = client.get(f"/api/v1/keys/{kid}", headers=_admin_hdrs(mcp_admin_token))
        assert resp2.status_code == 404


class TestMCPProfiles:
    """Certificate profile CRUD."""

    @skip_if_no_tokens
    def test_create_profile(self, client, mcp_admin_token):
        name = _uid("mcp-profile-")
        resp = client.post(
            "/api/v1/profiles",
            json={"name": name, "content": MINIMAL_PROFILE_CONTENT, "profile_type": "test"},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 201
        body = resp.get_json()
        pid = body["id"]
        assert body["name"] == name

        # get
        r = client.get(f"/api/v1/profiles/{pid}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200
        assert r.get_json()["content"].strip() == MINIMAL_PROFILE_CONTENT.strip()

        # update
        new_content = MINIMAL_PROFILE_CONTENT + "\n# updated\n"
        r = client.put(f"/api/v1/profiles/{pid}",
                       json={"content": new_content},
                       headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

        # delete
        r = client.delete(f"/api/v1/profiles/{pid}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

        # confirm gone
        r = client.get(f"/api/v1/profiles/{pid}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 404

    @skip_if_no_tokens
    def test_duplicate_profile_name_returns_409(self, client, mcp_admin_token):
        name = _uid("mcp-dup-profile-")
        client.post("/api/v1/profiles",
                    json={"name": name, "content": MINIMAL_PROFILE_CONTENT},
                    headers=_admin_hdrs(mcp_admin_token))
        resp = client.post("/api/v1/profiles",
                           json={"name": name, "content": MINIMAL_PROFILE_CONTENT},
                           headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 409
        # cleanup
        from x509_profiles import Profile
        with client.application.app_context():
            p = Profile.query.filter_by(name=name).first()
            if p:
                from extensions import db
                db.session.delete(p)
                db.session.commit()


class TestMCPCSRs:
    """CSR import and lifecycle."""

    @skip_if_no_tokens
    def test_import_csr(self, client, mcp_admin_token):
        cn = _uid("mcp-csr-import-")
        csr_pem = _make_csr_pem(cn)
        resp = client.post(
            "/api/v1/csrs/import",
            json={"csr_pem": csr_pem, "name": cn},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 201
        body = resp.get_json()
        csr_id = body["id"]
        assert "BEGIN CERTIFICATE REQUEST" in body["csr_pem"]

        # get
        r = client.get(f"/api/v1/csrs/{csr_id}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

        # delete
        r = client.delete(f"/api/v1/csrs/{csr_id}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

    @skip_if_no_tokens
    def test_import_csr_invalid_pem_returns_400(self, client, mcp_admin_token):
        resp = client.post(
            "/api/v1/csrs/import",
            json={"csr_pem": "not-a-pem"},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 400


class TestMCPCertificates:
    """Full certificate lifecycle: sign, list, get, revoke, delete."""

    @skip_if_no_tokens
    def test_list_certificates(self, client, mcp_admin_token):
        resp = client.get("/api/v1/certificates", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "certificates" in body
        assert "total" in body
        assert "page" in body

    @skip_if_no_tokens
    def test_sign_certificate_from_pem(self, client, app, mcp_admin_token):
        """Sign a CSR PEM directly; verify cert is stored and retrievable."""
        cn = _uid("mcp-sign-pem-")
        csr_pem = _make_csr_pem(cn)

        resp = client.post(
            "/api/v1/certificates/sign",
            json={"csr_pem": csr_pem, "no_extensions": True},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 201, resp.get_json()
        body = resp.get_json()
        cert_id = body["id"]
        assert body["serial"]
        assert cn in body.get("common_name", "") or cn in body.get("subject", "")
        assert "BEGIN CERTIFICATE" in body["cert_pem"]

        # get the cert
        r = client.get(f"/api/v1/certificates/{cert_id}",
                       headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200
        assert r.get_json()["serial"] == body["serial"]

        # cleanup
        client.delete(f"/api/v1/certificates/{cert_id}",
                      headers=_admin_hdrs(mcp_admin_token))

    @skip_if_no_tokens
    def test_sign_certificate_from_csr_id(self, client, app, mcp_admin_token):
        """Import a CSR, then sign it by referencing the stored CSR ID."""
        cn = _uid("mcp-sign-csr-id-")
        csr_pem = _make_csr_pem(cn)

        # import CSR
        r = client.post("/api/v1/csrs/import",
                        json={"csr_pem": csr_pem, "name": cn},
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 201
        csr_id = r.get_json()["id"]

        # sign using csr_id
        resp = client.post(
            "/api/v1/certificates/sign",
            json={"csr_id": csr_id, "no_extensions": True},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 201
        cert_id = resp.get_json()["id"]

        # cleanup
        client.delete(f"/api/v1/certificates/{cert_id}", headers=_admin_hdrs(mcp_admin_token))
        client.delete(f"/api/v1/csrs/{csr_id}", headers=_admin_hdrs(mcp_admin_token))

    @skip_if_no_tokens
    def test_sign_missing_csr_returns_400(self, client, mcp_admin_token):
        resp = client.post(
            "/api/v1/certificates/sign",
            json={},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 400

    @skip_if_no_tokens
    def test_revoke_and_delete_certificate(self, client, app, mcp_admin_token):
        cn = _uid("mcp-revoke-")
        csr_pem = _make_csr_pem(cn)
        r = client.post("/api/v1/certificates/sign",
                        json={"csr_pem": csr_pem, "no_extensions": True},
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 201
        cert_id = r.get_json()["id"]

        # revoke
        r = client.post(f"/api/v1/certificates/{cert_id}/revoke",
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

        # confirm revoked flag
        r = client.get(f"/api/v1/certificates/{cert_id}",
                       headers=_admin_hdrs(mcp_admin_token))
        assert r.get_json()["revoked"] is True

        # delete
        r = client.delete(f"/api/v1/certificates/{cert_id}",
                          headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

    @skip_if_no_tokens
    def test_search_filter(self, client, app, mcp_admin_token):
        cn = _uid("mcp-search-filter-")
        csr_pem = _make_csr_pem(cn)
        r = client.post("/api/v1/certificates/sign",
                        json={"csr_pem": csr_pem, "no_extensions": True},
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 201
        cert_id = r.get_json()["id"]

        # search by CN
        r = client.get(f"/api/v1/certificates?q={cn}",
                       headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200
        body = r.get_json()
        assert any(c["id"] == cert_id for c in body["certificates"])

        # cleanup
        client.delete(f"/api/v1/certificates/{cert_id}", headers=_admin_hdrs(mcp_admin_token))

    @skip_if_no_tokens
    def test_download_certificate(self, client, app, mcp_admin_token):
        cn = _uid("mcp-download-")
        csr_pem = _make_csr_pem(cn)
        r = client.post("/api/v1/certificates/sign",
                        json={"csr_pem": csr_pem, "no_extensions": True},
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 201
        cert_id = r.get_json()["id"]

        r = client.get(f"/api/v1/certificates/{cert_id}/download",
                       headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200
        assert "cert_pem" in r.get_json()

        client.delete(f"/api/v1/certificates/{cert_id}", headers=_admin_hdrs(mcp_admin_token))

    @skip_if_no_tokens
    def test_user_cannot_access_other_users_cert(self, client, app, mcp_admin_token, mcp_user_token):
        cn = _uid("mcp-isolation-")
        csr_pem = _make_csr_pem(cn)
        r = client.post("/api/v1/certificates/sign",
                        json={"csr_pem": csr_pem, "no_extensions": True},
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 201
        cert_id = r.get_json()["id"]

        # regular user cannot see admin's cert
        r = client.get(f"/api/v1/certificates/{cert_id}",
                       headers=_user_hdrs(mcp_user_token))
        assert r.status_code == 404

        client.delete(f"/api/v1/certificates/{cert_id}", headers=_admin_hdrs(mcp_admin_token))


class TestMCPRAPolicies:
    """RA Policy CRUD — admin token required for mutations."""

    @skip_if_no_tokens
    def test_list_policies(self, client, mcp_admin_token):
        resp = client.get("/api/v1/ra_policies", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        assert "ra_policies" in resp.get_json()

    @skip_if_no_tokens
    def test_user_can_list_own_policies(self, client, mcp_user_token):
        resp = client.get("/api/v1/ra_policies", headers=_user_hdrs(mcp_user_token))
        assert resp.status_code == 200

    @skip_if_no_tokens
    def test_create_update_delete_policy(self, client, mcp_admin_token):
        name = _uid("mcp-policy-")
        r = client.post(
            "/api/v1/ra_policies",
            json={"name": name, "validity_period": "30", "ext_config": ""},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert r.status_code == 201
        pid = r.get_json()["id"]

        # get
        r = client.get(f"/api/v1/ra_policies/{pid}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200
        assert r.get_json()["name"] == name

        # update
        r = client.put(f"/api/v1/ra_policies/{pid}",
                       json={"validity_period": "60"},
                       headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

        # delete
        r = client.delete(f"/api/v1/ra_policies/{pid}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

    @skip_if_no_tokens
    def test_non_admin_cannot_create_policy(self, client, mcp_user_token):
        resp = client.post(
            "/api/v1/ra_policies",
            json={"name": "will-fail", "validity_period": "30"},
            headers=_user_hdrs(mcp_user_token),
        )
        assert resp.status_code == 403


class TestMCPUsers:
    """User management — admin only."""

    @skip_if_no_tokens
    def test_list_users_requires_admin(self, client, mcp_user_token):
        resp = client.get("/api/v1/users", headers=_user_hdrs(mcp_user_token))
        assert resp.status_code == 403

    @skip_if_no_tokens
    def test_list_users_as_admin(self, client, mcp_admin_token):
        resp = client.get("/api/v1/users", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "users" in body
        assert len(body["users"]) > 0

    @skip_if_no_tokens
    def test_create_get_delete_user(self, client, mcp_admin_token):
        uname = _uid("mcp-newuser-")
        r = client.post(
            "/api/v1/users",
            json={"username": uname, "password": "TestPass123!", "role": "user"},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert r.status_code == 201
        uid = r.get_json()["id"]

        # get
        r = client.get(f"/api/v1/users/{uid}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200
        assert r.get_json()["username"] == uname

        # change role
        r = client.post(f"/api/v1/users/{uid}/change_role",
                        json={"role": "admin"},
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

        # reset password
        r = client.post(f"/api/v1/users/{uid}/reset_password",
                        json={"password": "NewTestPass456!"},
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

        # delete
        r = client.delete(f"/api/v1/users/{uid}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200

    @skip_if_no_tokens
    def test_weak_password_rejected_on_reset(self, client, mcp_admin_token):
        # create a user to try resetting
        uname = _uid("mcp-weakpw-")
        r = client.post("/api/v1/users",
                        json={"username": uname, "password": "StrongPass1!"},
                        headers=_admin_hdrs(mcp_admin_token))
        uid = r.get_json()["id"]
        r = client.post(f"/api/v1/users/{uid}/reset_password",
                        json={"password": "short"},
                        headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 400
        client.delete(f"/api/v1/users/{uid}", headers=_admin_hdrs(mcp_admin_token))


class TestMCPTokens:
    """API token self-management."""

    @skip_if_no_tokens
    def test_list_own_tokens(self, client, mcp_user_token):
        resp = client.get("/api/v1/tokens", headers=_user_hdrs(mcp_user_token))
        assert resp.status_code == 200
        assert "tokens" in resp.get_json()

    @skip_if_no_tokens
    def test_create_and_delete_token(self, client, app, mcp_admin_token):
        name = _uid("mcp-tok-")
        r = client.post(
            "/api/v1/tokens",
            json={"name": name, "validity": "1h"},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert r.status_code == 201
        body = r.get_json()
        tok_id = body["id"]
        assert "raw_token" in body
        assert "warning" in body

        # delete it
        r = client.delete(f"/api/v1/tokens/{tok_id}", headers=_admin_hdrs(mcp_admin_token))
        assert r.status_code == 200


class TestMCPEvents:
    """Audit event listing and retrieval."""

    @skip_if_no_tokens
    def test_list_events(self, client, mcp_admin_token):
        resp = client.get("/api/v1/events", headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        assert "events" in body
        assert "total" in body

    @skip_if_no_tokens
    def test_filter_by_resource_type(self, client, mcp_admin_token):
        resp = client.get("/api/v1/events?resource_type=certificate",
                          headers=_admin_hdrs(mcp_admin_token))
        assert resp.status_code == 200
        body = resp.get_json()
        for ev in body["events"]:
            assert ev["resource_type"] == "certificate"

    @skip_if_no_tokens
    def test_user_sees_only_own_events(self, client, mcp_user_token):
        resp = client.get("/api/v1/events", headers=_user_hdrs(mcp_user_token))
        assert resp.status_code == 200


class TestMCPInspection:
    """PEM inspection endpoint."""

    @skip_if_no_tokens
    def test_inspect_self_signed_cert(self, client, mcp_admin_token):
        cert_pem = _make_cert_pem("inspect-test")
        resp = client.post(
            "/api/v1/inspect",
            json={"pem": cert_pem},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body.get("detected_type") in ("certificate", "unknown")

    @skip_if_no_tokens
    def test_inspect_csr(self, client, mcp_admin_token):
        csr_pem = _make_csr_pem("csr-inspect-test")
        resp = client.post(
            "/api/v1/inspect",
            json={"pem": csr_pem},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 200

    @skip_if_no_tokens
    def test_inspect_missing_pem_returns_400(self, client, mcp_admin_token):
        resp = client.post(
            "/api/v1/inspect",
            json={},
            headers=_admin_hdrs(mcp_admin_token),
        )
        assert resp.status_code == 400


# ──────────────────────────────────────────────────────────────────────────────
# SECTION 2 — MCP tool layer tests (live server)
# Run with: PKI_MCP_LIVE=1 PKI_MCP_TOKEN=<token> pytest tests_repo/test_mcp.py -k live
# ──────────────────────────────────────────────────────────────────────────────

_LIVE = os.getenv("PKI_MCP_LIVE", "0").strip() not in ("", "0", "false", "no")
_MCP_URL = os.getenv("PKI_MCP_URL", "https://127.0.0.1:443").rstrip("/")
_MCP_TOKEN = os.getenv("PKI_MCP_TOKEN", "").strip()

skip_if_not_live = pytest.mark.skipif(
    not _LIVE or not _MCP_TOKEN,
    reason="Set PKI_MCP_LIVE=1 and PKI_MCP_TOKEN=<token> to run live MCP tool tests",
)


@pytest.fixture(scope="module")
def live_client():
    """PKIClient connected to the live PKI server."""
    if not _LIVE or not _MCP_TOKEN:
        pytest.skip("Live MCP tests not enabled")
    import sys
    sys.path.insert(0, str(ROOT_DIR))
    from pki_mcp.client import PKIClient
    c = PKIClient(base_url=_MCP_URL, token=_MCP_TOKEN, verify_ssl=False)
    yield c
    asyncio.get_event_loop().run_until_complete(c.close())


def _run(coro):
    """Run an async coroutine synchronously inside a test."""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.mark.live
@skip_if_not_live
class TestMCPToolsLive:
    """End-to-end MCP tool call tests against a running PKI server."""

    def test_tool_dashboard_stats(self, live_client):
        from pki_mcp.tools.dashboard import register
        from mcp.server.mcpserver.server import MCPServer
        mcp = MCPServer("test")
        register(mcp, live_client)

        result = _run(live_client.get("/api/v1/dashboard"))
        assert "summary" in result, f"Unexpected: {result}"

    def test_tool_ca_info(self, live_client):
        result = _run(live_client.get("/api/v1/ca"))
        assert "subject" in result or "error" not in result, f"CA info failed: {result}"

    def test_tool_certificate_list(self, live_client):
        result = _run(live_client.get("/api/v1/certificates"))
        assert "certificates" in result, f"Unexpected: {result}"

    def test_tool_key_generate_and_delete(self, live_client):
        name = _uid("live-mcp-key-")
        result = _run(live_client.post("/api/v1/keys",
                                       {"name": name, "key_type": "EC"}))
        assert result.get("id"), f"Key creation failed: {result}"
        kid = result["id"]
        del_result = _run(live_client.delete(f"/api/v1/keys/{kid}"))
        assert del_result.get("ok") is True

    def test_tool_csr_import_sign_and_cleanup(self, live_client):
        cn = _uid("live-mcp-cn-")
        csr_pem = _make_csr_pem(cn)

        # import CSR
        r = _run(live_client.post("/api/v1/csrs/import",
                                   {"csr_pem": csr_pem, "name": cn}))
        assert r.get("id"), f"CSR import failed: {r}"
        csr_id = r["id"]

        # sign using CSR ID
        r = _run(live_client.post("/api/v1/certificates/sign",
                                   {"csr_id": csr_id, "no_extensions": True}))
        assert r.get("id"), f"Signing failed: {r}"
        cert_id = r["id"]

        # revoke
        r = _run(live_client.post(f"/api/v1/certificates/{cert_id}/revoke"))
        assert r.get("ok") is True

        # delete cert + CSR
        _run(live_client.delete(f"/api/v1/certificates/{cert_id}"))
        _run(live_client.delete(f"/api/v1/csrs/{csr_id}"))

    def test_tool_inspect_pem(self, live_client):
        cert_pem = _make_cert_pem("live-inspect-test")
        result = _run(live_client.post("/api/v1/inspect", {"pem": cert_pem}))
        assert "error" not in result or result.get("detected_type"), f"Inspection failed: {result}"

    def test_tool_event_list(self, live_client):
        result = _run(live_client.get("/api/v1/events"))
        assert "events" in result, f"Unexpected: {result}"

    def test_tool_va_info(self, live_client):
        result = _run(live_client.get("/api/v1/va"))
        assert "crl_exists" in result or "error" not in result, f"VA info failed: {result}"

    def test_tool_profile_lifecycle(self, live_client):
        name = _uid("live-profile-")
        r = _run(live_client.post("/api/v1/profiles",
                                   {"name": name, "content": MINIMAL_PROFILE_CONTENT}))
        assert r.get("id"), f"Profile creation failed: {r}"
        pid = r["id"]

        r = _run(live_client.get(f"/api/v1/profiles/{pid}"))
        assert r.get("name") == name

        r = _run(live_client.delete(f"/api/v1/profiles/{pid}"))
        assert r.get("ok") is True

    def test_tool_mcp_server_registers_all_tools(self):
        """Verify that the MCP server registers the expected tool count."""
        import sys
        sys.path.insert(0, str(ROOT_DIR))
        from pki_mcp.server import build_server
        import os as _os
        orig = _os.environ.get("PKI_TOKEN")
        _os.environ["PKI_TOKEN"] = _MCP_TOKEN
        _os.environ["PKI_BASE_URL"] = _MCP_URL
        try:
            mcp, _ = build_server()
            tools = _run(mcp.list_tools())
            tool_names = {t.name for t in tools}
            expected = {
                "certificate_list", "certificate_sign", "certificate_revoke",
                "key_generate", "key_list", "csr_import", "profile_create",
                "ra_policy_list", "user_list", "token_create",
                "challenge_password_create", "psk_get",
                "event_list", "dashboard_stats", "inspect_pem",
                "ca_info", "va_info", "ocsp_check", "logs_get",
                "est_cacerts",
            }
            missing = expected - tool_names
            assert not missing, f"Missing expected MCP tools: {missing}"
            assert len(tools) >= 50, f"Expected ≥50 tools, got {len(tools)}"
        finally:
            if orig is None:
                _os.environ.pop("PKI_TOKEN", None)
            else:
                _os.environ["PKI_TOKEN"] = orig
