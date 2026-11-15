import sqlite3
import shutil
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from asn1crypto.cms import ContentInfo
from asn1crypto.csr import CertificationRequest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID, ObjectIdentifier
from flask import Flask
from werkzeug.serving import make_server

from builders import PKIMessageBuilder, Signer
from enterprise.scep import scep_app
from enums import MessageType
from envelope import PKCSPKIEnvelopeBuilder
from message import SCEPMessage


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])


def _certificate(subject, key, issuer, issuer_key, before, after, ca=False):
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def _csr(key, subject, challenge=None, san=None):
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if challenge:
        builder = builder.add_attribute(ObjectIdentifier("1.2.840.113549.1.9.7"), challenge.encode())
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return builder.sign(key, hashes.SHA256())


def _request(csr, ca_cert, signer_cert, signer_key, message_type=MessageType.PKCSReq):
    envelope, _, _ = (
        PKCSPKIEnvelopeBuilder()
        .encrypt(csr.public_bytes(serialization.Encoding.DER), "aes256")
        .add_recipient(ca_cert)
        .finalize()
    )
    return (
        PKIMessageBuilder()
        .message_type(message_type)
        .transaction_id("test-transaction")
        .sender_nonce()
        .pki_envelope(envelope)
        .add_signer(Signer(signer_cert, signer_key, "sha256"))
        .finalize()
        .dump()
    )


@pytest.fixture
def scep_server(tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    ca_key = _key()
    ca_name = _name("Test CA")
    ca_cert = _certificate(ca_name, ca_key, ca_name, ca_key, now - timedelta(days=1), now + timedelta(days=365), ca=True)
    cert_path = tmp_path / "ca.pem"
    key_path = tmp_path / "ca.key"
    cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(ca_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    ext_path = tmp_path / "ext.cnf"
    ext_path.write_text("[v3_ext]\nbasicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:policy.example\n")
    db_path = tmp_path / "test.sqlite"
    with sqlite3.connect(db_path) as conn:
        conn.executescript("""
            CREATE TABLE certificates (id INTEGER PRIMARY KEY, subject TEXT, serial TEXT,
                cert_pem TEXT, issued_via TEXT, user_id INTEGER, revoked INTEGER DEFAULT 0,
                not_valid_before TEXT, not_valid_after TEXT);
            CREATE TABLE challenge_passwords (value TEXT, consumed INTEGER, user_id INTEGER,
                validity TEXT, created_at TEXT, usage_mode TEXT, use_count INTEGER, last_used_at TEXT);
        """)
        conn.execute(
            "INSERT INTO challenge_passwords VALUES (?, 0, 42, ?, ?, 'single_use', 0, NULL)",
            ("one-time", "60m", now.strftime("%Y-%m-%d %H:%M:%S UTC")),
        )

    class PolicyManager:
        def get_protocol_default(self, protocol):
            return {}

        def get_validity_days(self, policy):
            return 30

        @contextmanager
        def temp_extfile(self, policy):
            yield str(ext_path)

    monkeypatch.setattr("enterprise.scep._get_ra_mgr", lambda: PolicyManager())
    app = Flask(__name__)
    app.config.update(
        TESTING=True, SCEP_ENABLED=True, SCEP_CHALLENGE_PASSWORD_ENABLED=True,
        SCEP_CERTIFICATE_RENEWAL_ENABLED=True, SUBCA_KEY_PATH=str(key_path),
        SUBCA_CERT_PATH=str(cert_path), CHAIN_FILE_PATH=str(cert_path), DB_PATH=str(db_path),
    )
    app.register_blueprint(scep_app)
    return app, ca_cert, ca_key, db_path


def _post(app, request_bytes):
    return app.test_client().post("/scep?operation=PKIOperation", data=request_bytes)


def _enroll(scep_server):
    app, ca_cert, _, db_path = scep_server
    key = _key()
    subject = _name("device")
    now = datetime.now(timezone.utc)
    self_signed = _certificate(subject, key, subject, key, now - timedelta(days=1), now + timedelta(days=1))
    response = _post(app, _request(_csr(key, subject, "one-time"), ca_cert, self_signed, key))
    assert response.status_code == 200
    message = SCEPMessage.parse(response.data)
    issued = pkcs7.load_der_pkcs7_certificates(message.get_decrypted_envelope_data(self_signed, key))[0]
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT consumed, use_count FROM challenge_passwords").fetchone() == (1, 1)
    return key, issued


def test_renewal_capability_follows_configuration(scep_server):
    app, _, _, _ = scep_server
    client = app.test_client()
    assert b"Renewal\n" in client.get("/scep?operation=GetCACaps").data
    app.config["SCEP_CERTIFICATE_RENEWAL_ENABLED"] = False
    assert b"Renewal\n" not in client.get("/scep?operation=GetCACaps").data


@pytest.mark.parametrize("message_type", [MessageType.PKCSReq, MessageType.RenewalReq])
def test_password_free_renewal_retains_owner_and_applies_policy(scep_server, message_type):
    app, ca_cert, _, db_path = scep_server
    key, old = _enroll(scep_server)
    csr = _csr(key, old.subject, san="requested.example")
    response = _post(app, _request(csr, ca_cert, old, key, message_type))
    assert response.status_code == 200
    message = SCEPMessage.parse(response.data)
    new = pkcs7.load_der_pkcs7_certificates(message.get_decrypted_envelope_data(old, key))[0]
    assert new.serial_number != old.serial_number
    assert new.subject == old.subject
    assert new.public_key().public_numbers() == old.public_key().public_numbers()
    assert new.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ["policy.example"]
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT user_id, revoked FROM certificates ORDER BY id").fetchall() == [(42, 0), (42, 0)]
        assert conn.execute("SELECT use_count FROM challenge_passwords").fetchone() == (1,)
        dates = conn.execute("SELECT not_valid_before, not_valid_after FROM certificates WHERE serial = ?", (hex(new.serial_number),)).fetchone()
        assert dates == (new.not_valid_before_utc.isoformat(), new.not_valid_after_utc.isoformat())


@pytest.mark.parametrize("case", ["disabled", "revoked", "unknown", "expired", "subject", "key"])
def test_renewal_rejects_invalid_authentication(scep_server, case):
    app, ca_cert, ca_key, db_path = scep_server
    key, old = _enroll(scep_server)
    subject = old.subject
    csr_key = key
    if case == "disabled":
        app.config["SCEP_CERTIFICATE_RENEWAL_ENABLED"] = False
    elif case == "revoked":
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE certificates SET revoked = 1")
    elif case == "unknown":
        with sqlite3.connect(db_path) as conn:
            conn.execute("DELETE FROM certificates")
    elif case == "expired":
        now = datetime.now(timezone.utc)
        old = _certificate(subject, key, ca_cert.subject, ca_key, now - timedelta(days=3), now - timedelta(days=1))
    elif case == "subject":
        subject = _name("another-device")
    elif case == "key":
        csr_key = _key()
    request_bytes = _request(_csr(csr_key, subject), ca_cert, old, key, MessageType.RenewalReq)
    assert _post(app, request_bytes).status_code == 403


@pytest.mark.parametrize("part", ["signature", "content"])
def test_tampering_is_rejected(scep_server, part):
    app, ca_cert, _, _ = scep_server
    key, old = _enroll(scep_server)
    raw = _request(_csr(key, old.subject), ca_cert, old, key)
    message = ContentInfo.load(raw)
    if part == "signature":
        signature = message["content"]["signer_infos"][0]["signature"].native
        message["content"]["signer_infos"][0]["signature"] = bytes([signature[0] ^ 1]) + signature[1:]
    else:
        content = message["content"]["encap_content_info"]["content"].native
        message["content"]["encap_content_info"]["content"] = content[:-1] + bytes([content[-1] ^ 1])
    assert _post(app, message.dump()).status_code == 400


def test_invalid_csr_signature_is_rejected(scep_server):
    app, ca_cert, _, _ = scep_server
    key, old = _enroll(scep_server)
    csr = CertificationRequest.load(_csr(key, old.subject).public_bytes(serialization.Encoding.DER))
    signature = csr["signature"].native
    csr["signature"] = bytes([signature[0] ^ 1]) + signature[1:]
    invalid = x509.load_der_x509_csr(csr.dump())
    assert _post(app, _request(invalid, ca_cert, old, key)).status_code == 400


def test_certificate_signed_pkcsreq_cannot_bypass_disabled_renewal(scep_server):
    app, ca_cert, _, _ = scep_server
    key, old = _enroll(scep_server)
    app.config["SCEP_CERTIFICATE_RENEWAL_ENABLED"] = False
    app.config["SCEP_CHALLENGE_PASSWORD_ENABLED"] = False
    assert _post(app, _request(_csr(key, old.subject), ca_cert, old, key)).status_code == 403


def test_untrusted_certificate_cannot_authenticate_renewal(scep_server):
    app, ca_cert, _, _ = scep_server
    key = _key()
    foreign_key = _key()
    now = datetime.now(timezone.utc)
    foreign = _certificate(
        _name("device"), key, _name("foreign CA"), foreign_key,
        now - timedelta(days=1), now + timedelta(days=1),
    )
    assert _post(app, _request(_csr(key, foreign.subject), ca_cert, foreign, key)).status_code == 403


def test_initial_enrollment_still_requires_challenge(scep_server):
    app, ca_cert, _, _ = scep_server
    key = _key()
    subject = _name("new-device")
    now = datetime.now(timezone.utc)
    signer = _certificate(subject, key, subject, key, now - timedelta(days=1), now + timedelta(days=1))
    assert _post(app, _request(_csr(key, subject), ca_cert, signer, key)).status_code == 400


def test_sscep_enrollment_and_in_place_renewal(scep_server, tmp_path):
    executable = Path(__file__).parent / "sscep" / "build" / "Release" / "sscep.exe"
    if not executable.exists():
        pytest.skip("Bundled sscep executable is unavailable")
    app, ca_cert, _, _ = scep_server
    key = _key()
    subject = _name("sscep-device")
    key_path = tmp_path / "device.key"
    csr_path = tmp_path / "device.csr"
    cert_path = tmp_path / "device.crt"
    ca_path = tmp_path / "ca.pem"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    csr_path.write_bytes(_csr(key, subject, "one-time").public_bytes(serialization.Encoding.PEM))
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        command = [
            str(executable), "enroll", "-u", f"http://127.0.0.1:{server.server_port}/scep",
            "-k", str(key_path), "-r", str(csr_path), "-c", str(ca_path),
            "-l", str(cert_path), "-E", "aes", "-S", "sha256",
        ]
        initial = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert initial.returncode == 0, initial.stdout + initial.stderr
        old = x509.load_pem_x509_certificate(cert_path.read_bytes())
        csr_path.write_bytes(_csr(key, subject).public_bytes(serialization.Encoding.PEM))
        renewal = subprocess.run(
            command + ["-K", str(key_path), "-O", str(cert_path)],
            capture_output=True, text=True, timeout=30,
        )
        assert renewal.returncode == 0, renewal.stdout + renewal.stderr
        new = x509.load_pem_x509_certificate(cert_path.read_bytes())
        assert new.serial_number != old.serial_number
        assert new.subject == old.subject
        assert new.public_key().public_numbers() == old.public_key().public_numbers()
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_api_renewal_script_against_isolated_server(scep_server, tmp_path):
    executable = Path(__file__).parent / "sscep" / "build" / "Release" / "sscep.exe"
    script = Path(__file__).parent / "scripts" / "test_sscep_renew.ps1"
    powershell = shutil.which("powershell")
    if not executable.exists() or not powershell or not shutil.which("openssl"):
        pytest.skip("sscep, PowerShell, or OpenSSL is unavailable")
    app, _, _, _ = scep_server
    workspace = tmp_path / "workspace"
    client_dir = workspace / "tests" / "sscep" / "build" / "Release"
    client_dir.mkdir(parents=True)
    shutil.copy2(executable, client_dir / "sscep.exe")
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        (workspace / "config.ini").write_text(
            f"[DEFAULT]\nhttp_port = {server.server_port}\n"
            "[SCEP]\ncertificate_renewal_enabled = true\n",
            encoding="ascii",
        )
        result = subprocess.run(
            [powershell, "-ExecutionPolicy", "Bypass", "-File", str(script),
             "-ChallengePassword", "one-time", "-CommonName", "sscep-script-test"],
            cwd=workspace, capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "[OK] Renewal issued" in result.stdout
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
