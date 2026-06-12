import base64
import os
import subprocess
import tempfile
import time
import shutil
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


def _log_debug(logger, message, *args):
    if logger:
        logger.debug(message, *args)


def _run_command(cmd, logger, text=True, input_data=None, check=False):
    start = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=text, input=input_data, check=check)
    elapsed = time.monotonic() - start
    _log_debug(
        logger,
        "[INSPECT] cmd done rc=%s seconds=%.3f cmd=%s",
        proc.returncode,
        elapsed,
        " ".join(cmd)
    )
    return proc


def _read_file_text(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().strip()


def _convert_private_key_to_putty(path, logger):
    """Convert a private key PEM to PuTTY PPK text when possible.

    Returns: (ppk_text_or_none, error_or_none)
    """
    def _resolve_winscp():
        ws = shutil.which("winscp.com")
        if ws:
            return ws
        repo_root = Path(__file__).resolve().parent
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        pf64 = os.environ.get("ProgramFiles", r"C:\Program Files")
        candidates = [
            repo_root / "utils" / "winscp.com",
            repo_root / "utils" / "WinSCP.com",
            repo_root / "utils" / "winscp" / "winscp.com",
            Path(pf86) / "WinSCP" / "WinSCP.com",
            Path(pf64) / "WinSCP" / "WinSCP.com",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    def _resolve_puttygen():
        pg = shutil.which("puttygen")
        if pg:
            return pg
        repo_root = Path(__file__).resolve().parent
        candidates = [
            repo_root / "utils" / "puttygen",
            repo_root / "utils" / "puttygen.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    # PuTTY conversion is requested for RSA private keys in inspect UI.
    rsa_probe = _run_command(["openssl", "rsa", "-in", path, "-check", "-noout"], logger, text=True)
    if rsa_probe.returncode != 0:
        return None, "PuTTY conversion is available only for RSA private keys."

    ppk_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".ppk")
    ppk_tmp.close()
    try:
        is_windows = (os.name == "nt")
        if is_windows:
            winscp_bin = _resolve_winscp()
            if not winscp_bin:
                return None, "winscp.com is not available (PATH or Program Files WinSCP)."
            ws_cmd = [winscp_bin, "/keygen", path, "-o", ppk_tmp.name]
            ws_proc = _run_command(ws_cmd, logger, text=True)
            if ws_proc.returncode == 0 and os.path.exists(ppk_tmp.name) and os.path.getsize(ppk_tmp.name) > 0:
                return _read_file_text(ppk_tmp.name), None
            ws_err = (ws_proc.stderr or ws_proc.stdout or "").strip()
            return None, (ws_err or "WinSCP keygen did not produce a .ppk file.")

        puttygen_bin = _resolve_puttygen()
        if not puttygen_bin:
            return None, "puttygen is not available (install putty-tools or add puttygen to PATH)."

        attempts = [
            [puttygen_bin, path, "-o", ppk_tmp.name],
            [puttygen_bin, path, "-O", "private", "-o", ppk_tmp.name],
            [puttygen_bin, path, "-O", "private", "-o", ppk_tmp.name, "-C", "imported-openssh-key"],
        ]
        last_err = "puttygen did not produce a .ppk file."
        for cmd in attempts:
            try:
                if os.path.exists(ppk_tmp.name):
                    os.unlink(ppk_tmp.name)
            except OSError:
                pass
            proc = _run_command(cmd, logger, text=True)
            if proc.returncode == 0 and os.path.exists(ppk_tmp.name) and os.path.getsize(ppk_tmp.name) > 0:
                return _read_file_text(ppk_tmp.name), None
            last_err = (proc.stderr or proc.stdout or last_err).strip()
        return None, last_err
    finally:
        try:
            os.unlink(ppk_tmp.name)
        except OSError:
            pass


def run_inspect(
    data,
    der_types,
    convert_public_key_formats,
    convert_private_key_formats,
    build_cert_public_key_formats,
    certificate_to_dict,
    is_pqc_public_key,
    is_ssh2_supported,
    logger=None,
    include_formats=False
):
    formats = None
    if not data:
        _log_debug(logger, "[INSPECT] no data provided")
        return "No data provided.", None

    is_pem = data.startswith("-----BEGIN ")
    _log_debug(logger, "[INSPECT] start len=%s is_pem=%s include_formats=%s", len(data), is_pem, include_formats)

    if not is_pem:
        try:
            der_bytes = base64.b64decode(data)
        except Exception:
            _log_debug(logger, "[INSPECT] base64 decode failed")
            return "Failed to base64-decode input.", None

        fd, path = tempfile.mkstemp(suffix=".der")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(der_bytes)

        detected = None
        detected_cmd = None
        detected_out = None
        failures = []

        for label, subcmd in der_types:
            if label == "Private Key":
                cmd = ["openssl", "pkey", "-inform DER", "-in", path, "-noout", "-text"]
            elif label == "Public Key":
                cmd = ["openssl", "pkey", "-pubin", "-in", path, "-noout", "-text"]
            elif label == "OCSP Request":
                cmd = ["openssl", "ocsp", "-reqin", path, "-text", "-noverify"]
            elif label == "OCSP Response":
                cmd = ["openssl", "ocsp", "-respin", path, "-text", "-noverify"]
            elif label == "PKCS#12 / PFX":
                cmd = ["openssl"] + subcmd + [path]
            else:
                cmd = ["openssl", subcmd[0], "-inform", "DER", "-noout", "-in", path] + subcmd[1:]

            proc = _run_command(cmd, logger, text=True)
            out = proc.stdout.strip() or proc.stderr.strip()

            if proc.returncode == 0:
                detected = label
                detected_cmd = cmd
                detected_out = out
                _log_debug(logger, "[INSPECT] detected der type=%s cmd=%s", detected, " ".join(cmd))
                break
            failures.append((label, cmd, proc.returncode, out))

        if detected:
            header = f"Detected as: {detected}"
            cmd_line = f"$ {' '.join(detected_cmd)}"
            extra_sections = []
            if detected == "Public Key":
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_pem:
                    tmp_pem_path = tmp_pem.name
                try:
                    _run_command(
                        ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", path, "-out", tmp_pem_path],
                        logger,
                        text=True,
                        check=True
                    )
                    if include_formats:
                        pkcs8_pem = _read_file_text(tmp_pem_path)
                        pub_formats = convert_public_key_formats(tmp_pem_path)
                        errors = dict(pub_formats["errors"] or {})
                        if not pkcs8_pem:
                            errors["pkcs8"] = "OpenSSL conversion failed."
                        if pub_formats["openssh"]:
                            extra_sections.append("Converted Public Key (OpenSSH)\n" + pub_formats["openssh"])
                        if pub_formats["rfc4716"]:
                            extra_sections.append("Converted Public Key (RFC4716)\n" + pub_formats["rfc4716"])
                        if not extra_sections and pub_formats["errors"].get("openssh"):
                            extra_sections.append("Public Key format error\n" + pub_formats["errors"]["openssh"])
                        formats = {
                            "kind": "public_key",
                            "pkcs8": pkcs8_pem or None,
                            "openssh": pub_formats["openssh"],
                            "rfc4716": pub_formats["rfc4716"],
                            "errors": errors
                        }
                finally:
                    os.unlink(tmp_pem_path)
            elif detected == "Private Key":
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as tmp_pem:
                    tmp_pem_path = tmp_pem.name
                try:
                    _run_command(
                        ["openssl", "pkey", "-inform", "DER", "-in", path, "-out", tmp_pem_path],
                        logger,
                        text=True,
                        check=True
                    )
                    if include_formats:
                        pkcs8_pem = _read_file_text(tmp_pem_path)
                        priv_formats = convert_private_key_formats(tmp_pem_path)
                        errors = dict(priv_formats["errors"] or {})
                        if not pkcs8_pem:
                            errors["pkcs8"] = "OpenSSL conversion failed."
                        if priv_formats["pkcs1"]:
                            extra_sections.append("Converted Private Key (PKCS1)\n" + priv_formats["pkcs1"])
                        if priv_formats["sec1"]:
                            extra_sections.append("Converted Private Key (SEC1)\n" + priv_formats["sec1"])
                        if not extra_sections and priv_formats["errors"].get("private_formats"):
                            extra_sections.append("Private Key format error\n" + priv_formats["errors"]["private_formats"])
                        formats = {
                            "kind": "private_key",
                            "pkcs8": pkcs8_pem or None,
                            "pkcs1": priv_formats["pkcs1"],
                            "sec1": priv_formats["sec1"],
                            "putty_ppk": None,
                            "errors": errors
                        }
                        putty_ppk, putty_err = _convert_private_key_to_putty(tmp_pem_path, logger)
                        formats["putty_ppk"] = putty_ppk
                        if putty_err:
                            formats["errors"]["putty_ppk"] = putty_err
                finally:
                    os.unlink(tmp_pem_path)
            elif detected == "X.509 Certificate" and include_formats:
                try:
                    cert = x509.load_der_x509_certificate(der_bytes, default_backend())
                    cert_details = certificate_to_dict(cert)
                    pub_formats = build_cert_public_key_formats(cert)
                    formats = {
                        "kind": "certificate",
                        "public_pem": pub_formats["public_pem"],
                        "openssh": pub_formats["openssh"],
                        "rfc4716": pub_formats["rfc4716"],
                        "errors": pub_formats["errors"],
                        "is_pqc_key": is_pqc_public_key(cert_details),
                        "is_ssh2_key": is_ssh2_supported(cert_details)
                    }
                except Exception as e:
                    _log_debug(logger, "[INSPECT] cert parse failed: %s", e)
            os.remove(path)
            return "\n\n".join([header, cmd_line, detected_out] + extra_sections), formats

        lines = ["None of the DER options succeeded. Debug info:"]
        _log_debug(logger, "[INSPECT] no DER type matched, failures=%s", len(failures))
        for lbl, cmd, code, out in failures:
            lines.append(f"--- {lbl} (exit {code}) ---")
            lines.append(f"$ {' '.join(cmd)}")
            lines.append(out or "(no output)")
            lines.append("")
        os.remove(path)
        return "\n".join(lines), None

    fd, path = tempfile.mkstemp(suffix=".pem")
    os.close(fd)
    normalized = data.rstrip() + "\n"
    with open(path, "wb") as f:
        f.write(normalized.encode())

    hdr = data.splitlines()[0].strip()
    _log_debug(logger, "[INSPECT] pem header=%s", hdr)
    if hdr.startswith("-----BEGIN PRIVATE KEY") \
       or hdr.startswith("-----BEGIN RSA PRIVATE KEY") \
       or hdr.startswith("-----BEGIN EC PRIVATE KEY"):
        chosen = "Private Key"
    elif hdr.startswith("-----BEGIN PUBLIC KEY"):
        chosen = "Public Key"
    elif hdr.startswith("-----BEGIN OCSP REQUEST"):
        chosen = "OCSP Request"
    elif hdr.startswith("-----BEGIN OCSP RESPONSE"):
        chosen = "OCSP Response"
    elif hdr.startswith("-----BEGIN CERTIFICATE REQUEST"):
        chosen = "Certificate Signing Request"
    elif hdr.startswith("-----BEGIN CERTIFICATE"):
        chosen = "X.509 Certificate"
    elif hdr.startswith("-----BEGIN X509 CRL") or hdr.startswith("-----BEGIN CRL"):
        chosen = "Certificate Revocation List"
    elif hdr.startswith("-----BEGIN PKCS7") or hdr.startswith("-----BEGIN CMS"):
        chosen = "PKCS#7 / CMS"
    elif hdr.startswith("-----BEGIN PKCS12") or path.lower().endswith((".p12", ".pfx")):
        chosen = "PKCS#12 / PFX"
    else:
        chosen = "X.509 Certificate"

    subcmd = next(cmd for (lbl, cmd) in der_types if lbl == chosen)
    _log_debug(logger, "[INSPECT] chosen=%s", chosen)

    if chosen == "Private Key":
        cmd = ["openssl", "pkey", "-in", path, "-noout", "-text"]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    elif chosen == "Public Key":
        cmd = ["openssl", "pkey", "-pubin", "-in", path, "-noout", "-text"]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    elif chosen == "OCSP Response":
        cmd = ["openssl", "ocsp", "-respin", path, "-noout", "-text", "-noverify"]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    elif chosen == "OCSP Request":
        cmd = ["openssl", "ocsp", "-reqin", path, "-noout", "-text", "-noverify"]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    elif chosen == "PKCS#12 / PFX":
        cmd = ["openssl", *subcmd, path]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    else:
        cmd = ["openssl", *subcmd, "-in", path]
        proc = _run_command(cmd, logger, text=True)
        out, err = proc.stdout, proc.stderr

    header = f"Detected: {chosen}"
    cmd_line = f"$ {' '.join(cmd)}"
    body = out.strip() or err.strip()
    extra_sections = []
    if include_formats:
        if chosen == "Public Key":
            pub_formats = convert_public_key_formats(path)
            pkcs8_proc = _run_command(["openssl", "pkey", "-pubin", "-in", path], logger, text=True)
            pkcs8_pem = pkcs8_proc.stdout.strip()
            errors = dict(pub_formats["errors"] or {})
            if pkcs8_proc.returncode != 0 or not pkcs8_pem:
                errors["pkcs8"] = (pkcs8_proc.stderr or "OpenSSL conversion failed.").strip()
            if pub_formats["openssh"]:
                extra_sections.append("Converted Public Key (OpenSSH)\n" + pub_formats["openssh"])
            if pub_formats["rfc4716"]:
                extra_sections.append("Converted Public Key (RFC4716)\n" + pub_formats["rfc4716"])
            if not extra_sections and pub_formats["errors"].get("openssh"):
                extra_sections.append("Public Key format error\n" + pub_formats["errors"]["openssh"])
            formats = {
                "kind": "public_key",
                "pkcs8": pkcs8_pem or data,
                "openssh": pub_formats["openssh"],
                "rfc4716": pub_formats["rfc4716"],
                "errors": errors
            }
        elif chosen == "Private Key":
            priv_formats = convert_private_key_formats(path)
            pkcs8_proc = _run_command(["openssl", "pkey", "-in", path], logger, text=True)
            pkcs8_pem = pkcs8_proc.stdout.strip()
            errors = dict(priv_formats["errors"] or {})
            if pkcs8_proc.returncode != 0 or not pkcs8_pem:
                errors["pkcs8"] = (pkcs8_proc.stderr or "OpenSSL conversion failed.").strip()
            if priv_formats["pkcs1"]:
                extra_sections.append("Converted Private Key (PKCS1)\n" + priv_formats["pkcs1"])
            if priv_formats["sec1"]:
                extra_sections.append("Converted Private Key (SEC1)\n" + priv_formats["sec1"])
            if not extra_sections and priv_formats["errors"].get("private_formats"):
                extra_sections.append("Private Key format error\n" + priv_formats["errors"]["private_formats"])
            formats = {
                "kind": "private_key",
                "pkcs8": pkcs8_pem or data,
                "pkcs1": priv_formats["pkcs1"],
                "sec1": priv_formats["sec1"],
                "putty_ppk": None,
                "errors": errors
            }
            putty_ppk, putty_err = _convert_private_key_to_putty(path, logger)
            formats["putty_ppk"] = putty_ppk
            if putty_err:
                formats["errors"]["putty_ppk"] = putty_err
        elif chosen == "X.509 Certificate":
            try:
                cert = x509.load_pem_x509_certificate(normalized.encode("utf-8"), default_backend())
                cert_details = certificate_to_dict(cert)
                pub_formats = build_cert_public_key_formats(cert)
                formats = {
                    "kind": "certificate",
                    "public_pem": pub_formats["public_pem"],
                    "openssh": pub_formats["openssh"],
                    "rfc4716": pub_formats["rfc4716"],
                    "errors": pub_formats["errors"],
                    "is_pqc_key": is_pqc_public_key(cert_details),
                    "is_ssh2_key": is_ssh2_supported(cert_details)
                }
            except Exception as e:
                _log_debug(logger, "[INSPECT] cert parse failed: %s", e)
    os.remove(path)
    return "\n\n".join([header, cmd_line, body] + extra_sections), formats


def _name_string(name):
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _public_key_bytes(public_key):
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _extension_value(obj, oid):
    try:
        return obj.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _subject_alt_names(obj):
    san = _extension_value(obj, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if san is None:
        return []
    values = []
    for name in san:
        label = name.__class__.__name__
        value = getattr(name, "value", str(name))
        values.append(f"{label}:{value}")
    return sorted(values)


def _key_usage_tokens(obj):
    ku = _extension_value(obj, ExtensionOID.KEY_USAGE)
    if ku is None:
        return []
    flags = []
    names = (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    )
    for name in names:
        try:
            if getattr(ku, name):
                flags.append(name)
        except ValueError:
            continue
    return flags


def _eku_tokens(obj):
    eku = _extension_value(obj, ExtensionOID.EXTENDED_KEY_USAGE)
    if eku is None:
        return []
    values = []
    for oid in eku:
        values.append(getattr(oid, "_name", None) or oid.dotted_string)
    return sorted(values)


def _basic_constraints_summary(obj):
    bc = _extension_value(obj, ExtensionOID.BASIC_CONSTRAINTS)
    if bc is None:
        return None
    path_length = "none" if bc.path_length is None else str(bc.path_length)
    return {
        "ca": bool(bc.ca),
        "path_length": path_length,
    }


def _aki_hex(obj):
    aki = _extension_value(obj, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    if aki is None or aki.key_identifier is None:
        return None
    return aki.key_identifier.hex()


def _ski_hex(obj):
    ski = _extension_value(obj, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if ski is None:
        return None
    return ski.digest.hex()


def _common_name(name):
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def _oid_label(oid):
    return getattr(oid, "_name", None) or getattr(oid, "dotted_string", str(oid))


def _name_tokens(name):
    tokens = []
    for rdn in name.rdns:
        for attribute in rdn:
            tokens.append(f"{_oid_label(attribute.oid)}={attribute.value}")
    return sorted(tokens)


def _describe_name_diff(left_name, right_name, left_label="Left", right_label="Right"):
    left_tokens = _name_tokens(left_name)
    right_tokens = _name_tokens(right_name)
    missing = sorted(set(left_tokens) - set(right_tokens))
    added = sorted(set(right_tokens) - set(left_tokens))
    if not missing and not added:
        return "pass", "All subject attributes match.", missing, added
    details = []
    if missing:
        details.append(f"Missing from {right_label}: " + ", ".join(missing))
    if added:
        details.append(f"Added in {right_label}: " + ", ".join(added))
    return "warn", "\n".join(details), missing, added


def _describe_token_diff(left_tokens, right_tokens, left_label, right_label, empty_text):
    left_tokens = sorted(left_tokens or [])
    right_tokens = sorted(right_tokens or [])
    missing = sorted(set(left_tokens) - set(right_tokens))
    added = sorted(set(right_tokens) - set(left_tokens))
    if not missing and not added:
        return "pass", empty_text if not left_tokens and not right_tokens else ", ".join(right_tokens), missing, added
    details = []
    if missing:
        details.append(f"Missing from {right_label}: " + ", ".join(missing))
    if added:
        details.append(f"Added in {right_label}: " + ", ".join(added))
    return "warn", "\n".join(details), missing, added


def _digest_hex(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def _summarize_public_key(public_key):
    kind = type(public_key).__name__
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC {public_key.curve.name}"
    if isinstance(public_key, dsa.DSAPublicKey):
        return f"DSA {public_key.key_size}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    return kind


def _public_key_match(left_public_key, right_public_key):
    return _public_key_bytes(left_public_key) == _public_key_bytes(right_public_key)


def _load_certificate_any(blob):
    errors = []
    for loader, label in (
        (x509.load_pem_x509_certificate, "PEM certificate"),
        (x509.load_der_x509_certificate, "DER certificate"),
    ):
        try:
            return loader(blob, default_backend())
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    raise ValueError("; ".join(errors))


def _load_csr_any(blob):
    errors = []
    for loader, label in (
        (x509.load_pem_x509_csr, "PEM CSR"),
        (x509.load_der_x509_csr, "DER CSR"),
    ):
        try:
            return loader(blob, default_backend())
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    raise ValueError("; ".join(errors))


def _load_private_key_any(blob):
    errors = []
    for loader, label in (
        (serialization.load_pem_private_key, "PEM private key"),
        (serialization.load_der_private_key, "DER private key"),
    ):
        try:
            return loader(blob, password=None, backend=default_backend())
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    raise ValueError("; ".join(errors))


def _load_public_key_any(blob):
    errors = []
    for loader, label in (
        (serialization.load_pem_public_key, "PEM public key"),
        (serialization.load_der_public_key, "DER public key"),
    ):
        try:
            return loader(blob, backend=default_backend())
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    raise ValueError("; ".join(errors))


def _detect_input_object(blob):
    detectors = (
        ("csr", "CSR", _load_csr_any),
        ("certificate", "Certificate", _load_certificate_any),
        ("private_key", "Private key", _load_private_key_any),
        ("public_key", "Public key", _load_public_key_any),
    )
    errors = []
    for kind, label, loader in detectors:
        try:
            return kind, label, loader(blob)
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    raise ValueError("; ".join(errors))


def _input_text_to_bytes(text):
    normalized = (text or "").strip()
    if not normalized:
        return b""
    return (normalized.rstrip() + "\n").encode("utf-8")


def _prepare_input_slot(slot_name, text_value="", upload_bytes=None, upload_name=""):
    bytes_value = upload_bytes if upload_bytes else _input_text_to_bytes(text_value)
    source = f"upload:{upload_name}" if upload_bytes and upload_name else "paste"
    return {
        "slot": slot_name,
        "text": (text_value or "").strip(),
        "bytes": bytes_value,
        "source": source,
        "filename": upload_name or "",
    }


def _slot_has_value(slot):
    return bool(slot.get("bytes"))


def _detect_slot_object(slot):
    blob = slot.get("bytes", b"")
    if not blob:
        return None
    kind, detected_label, obj = _detect_input_object(blob)
    return {
        "slot": slot["slot"],
        "kind": kind,
        "label": detected_label,
        "object": obj,
        "filename": slot.get("filename", ""),
        "source": slot.get("source", ""),
    }


def _verify_cert_signature(cert, ca_cert):
    public_key = ca_cert.public_key()
    signature_hash = cert.signature_hash_algorithm
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            signature_hash,
        )
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(signature_hash),
        )
        return
    if isinstance(public_key, dsa.DSAPublicKey):
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            signature_hash,
        )
        return
    if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        return
    raise ValueError(f"Unsupported CA public key type: {type(public_key).__name__}")


def _append_check(checks, category, status, label, details):
    checks.append({
        "category": category,
        "status": status,
        "label": label,
        "details": details,
    })


def build_sanity_report(csr_pem, cert_pem, ca_pem):
    csr_pem = (csr_pem or "").strip()
    cert_pem = (cert_pem or "").strip()
    ca_pem = (ca_pem or "").strip()
    checks = []

    csr = None
    cert = None
    ca_cert = None

    if not any((csr_pem, cert_pem, ca_pem)):
        return None

    if csr_pem:
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"), default_backend())
            _append_check(checks, "Inputs", "pass", "CSR parsed", "CSR input was parsed successfully.")
        except Exception as exc:
            _append_check(checks, "Inputs", "fail", "CSR parse failed", str(exc))

    if cert_pem:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"), default_backend())
            _append_check(checks, "Inputs", "pass", "Certificate parsed", "Certificate input was parsed successfully.")
        except Exception as exc:
            _append_check(checks, "Inputs", "fail", "Certificate parse failed", str(exc))

    if ca_pem:
        try:
            ca_cert = x509.load_pem_x509_certificate(ca_pem.encode("utf-8"), default_backend())
            _append_check(checks, "Inputs", "pass", "CA certificate parsed", "CA input was parsed successfully.")
        except Exception as exc:
            _append_check(checks, "Inputs", "fail", "CA certificate parse failed", str(exc))

    if csr and cert:
        csr_subject = _name_string(csr.subject)
        cert_subject = _name_string(cert.subject)
        if csr_subject == cert_subject:
            _append_check(checks, "CSR vs Certificate", "pass", "Subject matches", cert_subject)
        else:
            _append_check(
                checks,
                "CSR vs Certificate",
                "warn",
                "Subject differs",
                f"CSR: {csr_subject}\nCertificate: {cert_subject}"
            )

        csr_key = _public_key_bytes(csr.public_key())
        cert_key = _public_key_bytes(cert.public_key())
        if csr_key == cert_key:
            _append_check(checks, "CSR vs Certificate", "pass", "Public key matches", "Certificate uses the CSR public key.")
        else:
            _append_check(checks, "CSR vs Certificate", "fail", "Public key differs", "Certificate public key does not match CSR.")

        csr_sans = _subject_alt_names(csr)
        cert_sans = _subject_alt_names(cert)
        if csr_sans == cert_sans:
            _append_check(checks, "CSR vs Certificate", "pass", "SubjectAltName matches", ", ".join(cert_sans) if cert_sans else "No SAN extension in either object.")
        else:
            missing = sorted(set(csr_sans) - set(cert_sans))
            extra = sorted(set(cert_sans) - set(csr_sans))
            details = []
            if missing:
                details.append("Missing from certificate: " + ", ".join(missing))
            if extra:
                details.append("Added in certificate: " + ", ".join(extra))
            _append_check(checks, "CSR vs Certificate", "warn", "SubjectAltName differs", "\n".join(details) or "SAN values differ.")

        csr_ku = _key_usage_tokens(csr)
        cert_ku = _key_usage_tokens(cert)
        if csr_ku == cert_ku:
            _append_check(checks, "CSR vs Certificate", "pass", "KeyUsage matches", ", ".join(cert_ku) if cert_ku else "No KeyUsage extension in either object.")
        else:
            _append_check(checks, "CSR vs Certificate", "warn", "KeyUsage differs", f"CSR: {', '.join(csr_ku) or 'none'}\nCertificate: {', '.join(cert_ku) or 'none'}")

        csr_eku = _eku_tokens(csr)
        cert_eku = _eku_tokens(cert)
        if csr_eku == cert_eku:
            _append_check(checks, "CSR vs Certificate", "pass", "ExtendedKeyUsage matches", ", ".join(cert_eku) if cert_eku else "No ExtendedKeyUsage extension in either object.")
        else:
            _append_check(checks, "CSR vs Certificate", "warn", "ExtendedKeyUsage differs", f"CSR: {', '.join(csr_eku) or 'none'}\nCertificate: {', '.join(cert_eku) or 'none'}")

        csr_bc = _basic_constraints_summary(csr)
        cert_bc = _basic_constraints_summary(cert)
        if csr_bc == cert_bc:
            detail = "No BasicConstraints extension in either object." if csr_bc is None else f"CA={cert_bc['ca']}, path_length={cert_bc['path_length']}"
            _append_check(checks, "CSR vs Certificate", "pass", "BasicConstraints matches", detail)
        else:
            _append_check(checks, "CSR vs Certificate", "warn", "BasicConstraints differs", f"CSR: {csr_bc}\nCertificate: {cert_bc}")

    if cert and ca_cert:
        issuer = _name_string(cert.issuer)
        ca_subject = _name_string(ca_cert.subject)
        if issuer == ca_subject:
            _append_check(checks, "Certificate vs CA", "pass", "Issuer matches CA subject", issuer)
        else:
            _append_check(checks, "Certificate vs CA", "fail", "Issuer differs from CA subject", f"Issuer: {issuer}\nCA Subject: {ca_subject}")

        try:
            _verify_cert_signature(cert, ca_cert)
            _append_check(checks, "Certificate vs CA", "pass", "Certificate signature verifies", "Certificate signature was verified with the CA public key.")
        except Exception as exc:
            _append_check(checks, "Certificate vs CA", "fail", "Certificate signature verification failed", str(exc))

        ca_bc = _basic_constraints_summary(ca_cert)
        if ca_bc and ca_bc["ca"]:
            _append_check(checks, "Certificate vs CA", "pass", "CA basic constraints are valid", f"CA={ca_bc['ca']}, path_length={ca_bc['path_length']}")
        else:
            _append_check(checks, "Certificate vs CA", "fail", "Selected issuer is not a CA", "CA certificate is missing BasicConstraints CA=TRUE.")

        aki = _aki_hex(cert)
        ski = _ski_hex(ca_cert)
        if aki and ski:
            if aki == ski:
                _append_check(checks, "Certificate vs CA", "pass", "AKI matches CA SKI", aki)
            else:
                _append_check(checks, "Certificate vs CA", "warn", "AKI differs from CA SKI", f"AKI: {aki}\nCA SKI: {ski}")
        else:
            _append_check(checks, "Certificate vs CA", "info", "AKI/SKI comparison skipped", "Certificate AKI or CA SKI is missing.")

    if cert:
        now = time.time()
        not_before = cert.not_valid_before_utc.timestamp()
        not_after = cert.not_valid_after_utc.timestamp()
        if now < not_before:
            _append_check(checks, "General sanity", "fail", "Certificate not yet valid", f"Not valid before {cert.not_valid_before_utc.isoformat()}")
        elif now > not_after:
            _append_check(checks, "General sanity", "fail", "Certificate expired", f"Not valid after {cert.not_valid_after_utc.isoformat()}")
        else:
            _append_check(checks, "General sanity", "pass", "Certificate validity window is current", f"Valid until {cert.not_valid_after_utc.isoformat()}")

        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < 2048:
                _append_check(checks, "General sanity", "warn", "Weak RSA key size", f"RSA key size is {public_key.key_size} bits.")
            else:
                _append_check(checks, "General sanity", "pass", "RSA key size is acceptable", f"RSA key size is {public_key.key_size} bits.")

        sig_oid = getattr(cert.signature_algorithm_oid, "_name", None) or cert.signature_algorithm_oid.dotted_string
        sig_name = sig_oid.lower()
        if "md5" in sig_name or "sha1" in sig_name:
            _append_check(checks, "General sanity", "warn", "Weak signature algorithm", sig_oid)
        else:
            _append_check(checks, "General sanity", "pass", "Signature algorithm looks acceptable", sig_oid)

        cert_bc = _basic_constraints_summary(cert)
        if cert_bc and cert_bc["ca"]:
            _append_check(checks, "General sanity", "info", "Certificate is marked as a CA", f"CA={cert_bc['ca']}, path_length={cert_bc['path_length']}")

        cn = _common_name(cert.subject)
        sans = _subject_alt_names(cert)
        if cn and "." in cn and not sans:
            _append_check(checks, "General sanity", "warn", "Hostname-like CN without SAN", f"CN={cn}")

    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    categories = {}
    for check in checks:
        counts[check["status"]] = counts.get(check["status"], 0) + 1
        categories.setdefault(check["category"], []).append(check)

    return {
        "counts": counts,
        "categories": categories,
        "has_errors": counts["fail"] > 0,
    }


def _new_check_report(mode, title, description):
    return {
        "mode": mode,
        "title": title,
        "description": description,
        "counts": {"pass": 0, "warn": 0, "fail": 0, "info": 0},
        "categories": {},
        "inputs": [],
        "has_errors": False,
        "headline_status": "info",
        "headline": "",
        "entities": [],
        "relationships": [],
    }


def _add_check_item(report, category, status, label, details):
    report["counts"][status] = report["counts"].get(status, 0) + 1
    report["categories"].setdefault(category, []).append({
        "category": category,
        "status": status,
        "label": label,
        "details": details,
    })


def _add_input_summary(report, slot, expected_label, detected_label=None, status="info", details=""):
    report["inputs"].append({
        "slot": slot,
        "expected_label": expected_label,
        "detected_label": detected_label or "Not detected",
        "status": status,
        "details": details,
    })


def _add_entity(report, entity_id, title, subtitle="", kind="", slot=None, status="info"):
    for entity in report["entities"]:
        if entity["id"] == entity_id:
            return
    report["entities"].append({
        "id": entity_id,
        "title": title,
        "subtitle": subtitle,
        "kind": kind,
        "slot": slot,
        "status": status,
    })


def _add_relationship(report, source_id, target_id, status, label, details=""):
    report["relationships"].append({
        "source": source_id,
        "target": target_id,
        "status": status,
        "label": label,
        "details": details,
    })


def _finalize_report(report):
    report["has_errors"] = report["counts"]["fail"] > 0
    if report["counts"]["fail"]:
        report["headline_status"] = "fail"
    elif report["counts"]["warn"]:
        report["headline_status"] = "warn"
    elif report["counts"]["pass"]:
        report["headline_status"] = "pass"
    else:
        report["headline_status"] = "info"
    return report


def _parse_required_slot(report, raw_slot, expected_kind, expected_label):
    blob = raw_slot.get("bytes", b"")
    if not blob:
        _add_input_summary(report, raw_slot["slot"], expected_label, status="fail", details="No input provided.")
        _add_check_item(report, "Inputs", "fail", f"{expected_label} missing", "Provide pasted text or upload a file.")
        return None
    try:
        kind, detected_label, obj = _detect_input_object(blob)
    except Exception as exc:
        _add_input_summary(report, raw_slot["slot"], expected_label, status="fail", details=str(exc))
        _add_check_item(report, "Inputs", "fail", f"{expected_label} parse failed", str(exc))
        return None
    if expected_kind and kind != expected_kind:
        _add_input_summary(report, raw_slot["slot"], expected_label, detected_label, status="fail", details=f"Expected {expected_label.lower()}, detected {detected_label.lower()}.")
        _add_check_item(report, "Inputs", "fail", f"{expected_label} type mismatch", f"Expected {expected_label.lower()}, detected {detected_label.lower()}.")
        return None
    subject = getattr(obj, "subject", None)
    summary_bits = [f"Detected {detected_label.lower()}"]
    if subject is not None:
        summary_bits.append(_name_string(subject))
    else:
        summary_bits.append(_summarize_public_key(obj.public_key() if hasattr(obj, "public_key") else obj))
    _add_input_summary(report, raw_slot["slot"], expected_label, detected_label, status="pass", details="\n".join(summary_bits))
    _add_check_item(report, "Inputs", "pass", f"{expected_label} parsed", raw_slot["filename"] or raw_slot["source"])
    return obj


def _parse_object_slot(report, raw_slot, expected_label):
    blob = raw_slot.get("bytes", b"")
    if not blob:
        _add_input_summary(report, raw_slot["slot"], expected_label, status="fail", details="No input provided.")
        _add_check_item(report, "Inputs", "fail", f"{expected_label} missing", "Provide pasted text or upload a file.")
        return None, None
    try:
        kind, detected_label, obj = _detect_input_object(blob)
    except Exception as exc:
        _add_input_summary(report, raw_slot["slot"], expected_label, status="fail", details=str(exc))
        _add_check_item(report, "Inputs", "fail", f"{expected_label} parse failed", str(exc))
        return None, None
    if kind not in ("csr", "certificate"):
        _add_input_summary(report, raw_slot["slot"], expected_label, detected_label, status="fail", details="Expected a CSR or certificate.")
        _add_check_item(report, "Inputs", "fail", f"{expected_label} type mismatch", f"Expected CSR or certificate, detected {detected_label.lower()}.")
        return None, None
    _add_input_summary(report, raw_slot["slot"], expected_label, detected_label, status="pass", details=f"Detected {detected_label.lower()}\n{_name_string(obj.subject)}")
    _add_check_item(report, "Inputs", "pass", f"{expected_label} parsed", raw_slot["filename"] or raw_slot["source"])
    return kind, obj


def _parse_key_slot(report, raw_slot, expected_label):
    blob = raw_slot.get("bytes", b"")
    if not blob:
        _add_input_summary(report, raw_slot["slot"], expected_label, status="fail", details="No input provided.")
        _add_check_item(report, "Inputs", "fail", f"{expected_label} missing", "Provide pasted text or upload a file.")
        return None, None
    try:
        kind, detected_label, obj = _detect_input_object(blob)
    except Exception as exc:
        _add_input_summary(report, raw_slot["slot"], expected_label, status="fail", details=str(exc))
        _add_check_item(report, "Inputs", "fail", f"{expected_label} parse failed", str(exc))
        return None, None
    if kind not in ("private_key", "public_key"):
        _add_input_summary(report, raw_slot["slot"], expected_label, detected_label, status="fail", details="Expected a public or private key.")
        _add_check_item(report, "Inputs", "fail", f"{expected_label} type mismatch", f"Expected key material, detected {detected_label.lower()}.")
        return None, None
    key_obj = obj.public_key() if kind == "private_key" else obj
    detail = f"Detected {detected_label.lower()}\n{_summarize_public_key(key_obj)}"
    if kind == "private_key":
        detail += "\nComparison will use the private key's derived public key."
    _add_input_summary(report, raw_slot["slot"], expected_label, detected_label, status="pass", details=detail)
    _add_check_item(report, "Inputs", "pass", f"{expected_label} parsed", raw_slot["filename"] or raw_slot["source"])
    return kind, obj


def _build_csr_certificate_report(slots):
    report = _new_check_report(
        "csr_certificate",
        "CSR vs Certificate",
        "Compare requested subject, extensions, and public key material."
    )
    csr = _parse_required_slot(report, slots["primary"], "csr", "CSR")
    cert = _parse_required_slot(report, slots["secondary"], "certificate", "Certificate")
    if not (csr and cert):
        report["headline"] = "Unable to complete the CSR to certificate comparison."
        return _finalize_report(report)

    _add_entity(report, "csr", "CSR", _name_string(csr.subject), "csr", "primary", "info")
    _add_entity(report, "certificate", "Certificate", _name_string(cert.subject), "certificate", "secondary", "info")

    if _public_key_match(csr.public_key(), cert.public_key()):
        _add_check_item(report, "Relationship", "pass", "Public key matches", "The certificate uses the same public key as the CSR.")
        _add_relationship(report, "certificate", "csr", "pass", "Made from this CSR", "The certificate public key matches the CSR public key.")
    else:
        _add_check_item(report, "Relationship", "fail", "Public key differs", "The certificate public key does not match the CSR.")
        _add_relationship(report, "certificate", "csr", "fail", "Not made from this CSR", "The certificate public key does not match the CSR.")

    subject_status, subject_details, _, _ = _describe_name_diff(csr.subject, cert.subject, "CSR", "Certificate")
    _add_check_item(report, "Requested content", subject_status, "Subject attributes", subject_details)

    san_status, san_details, _, _ = _describe_token_diff(
        _subject_alt_names(csr),
        _subject_alt_names(cert),
        "CSR",
        "Certificate",
        "No SAN extension in either object."
    )
    _add_check_item(report, "Requested content", san_status, "SubjectAltName", san_details)

    ku_status, ku_details, _, _ = _describe_token_diff(
        _key_usage_tokens(csr),
        _key_usage_tokens(cert),
        "CSR",
        "Certificate",
        "No KeyUsage extension in either object."
    )
    _add_check_item(report, "Requested content", ku_status, "KeyUsage", ku_details)

    eku_status, eku_details, _, _ = _describe_token_diff(
        _eku_tokens(csr),
        _eku_tokens(cert),
        "CSR",
        "Certificate",
        "No ExtendedKeyUsage extension in either object."
    )
    _add_check_item(report, "Requested content", eku_status, "ExtendedKeyUsage", eku_details)

    csr_bc = _basic_constraints_summary(csr)
    cert_bc = _basic_constraints_summary(cert)
    if csr_bc == cert_bc:
        detail = "No BasicConstraints extension in either object." if csr_bc is None else f"CA={cert_bc['ca']}, path_length={cert_bc['path_length']}"
        _add_check_item(report, "Requested content", "pass", "BasicConstraints", detail)
    else:
        _add_check_item(report, "Requested content", "warn", "BasicConstraints", f"CSR: {csr_bc}\nCertificate: {cert_bc}")

    csr_fingerprint = _digest_hex(_public_key_bytes(csr.public_key()))
    cert_fingerprint = _digest_hex(_public_key_bytes(cert.public_key()))
    _add_check_item(report, "Fingerprints", "info", "Public key SHA-256", f"CSR: {csr_fingerprint}\nCertificate: {cert_fingerprint}")

    if report["counts"]["fail"]:
        report["headline"] = "The certificate does not fully match the CSR."
    elif report["counts"]["warn"]:
        report["headline"] = "The certificate was likely derived from the CSR, with some differences."
    else:
        report["headline"] = "The certificate cleanly matches the CSR request data."
    return _finalize_report(report)


def _build_ca_certificate_report(slots):
    report = _new_check_report(
        "ca_certificate",
        "CA vs Certificate",
        "Check whether the supplied CA issued the certificate."
    )
    ca_cert = _parse_required_slot(report, slots["primary"], "certificate", "CA certificate")
    cert = _parse_required_slot(report, slots["secondary"], "certificate", "Leaf certificate")
    if not (ca_cert and cert):
        report["headline"] = "Unable to determine issuer relationship."
        return _finalize_report(report)

    _add_entity(report, "ca", "CA Certificate", _name_string(ca_cert.subject), "ca_certificate", "primary", "info")
    _add_entity(report, "certificate", "Certificate", _name_string(cert.subject), "certificate", "secondary", "info")

    issued = True
    issuer = _name_string(cert.issuer)
    ca_subject = _name_string(ca_cert.subject)
    if issuer == ca_subject:
        _add_check_item(report, "Relationship", "pass", "Issuer matches CA subject", issuer)
    else:
        issued = False
        _add_check_item(report, "Relationship", "fail", "Issuer differs from CA subject", f"Issuer: {issuer}\nCA Subject: {ca_subject}")

    try:
        _verify_cert_signature(cert, ca_cert)
        _add_check_item(report, "Relationship", "pass", "Certificate signature verifies", "The certificate signature verifies with the CA public key.")
    except Exception as exc:
        issued = False
        _add_check_item(report, "Relationship", "fail", "Certificate signature verification failed", str(exc))

    ca_bc = _basic_constraints_summary(ca_cert)
    if ca_bc and ca_bc["ca"]:
        _add_check_item(report, "Relationship", "pass", "CA basic constraints are valid", f"CA={ca_bc['ca']}, path_length={ca_bc['path_length']}")
    else:
        issued = False
        _add_check_item(report, "Relationship", "fail", "Selected issuer is not a CA", "BasicConstraints CA=TRUE is missing.")

    aki = _aki_hex(cert)
    ski = _ski_hex(ca_cert)
    if aki and ski:
        if aki == ski:
            _add_check_item(report, "Relationship", "pass", "AKI matches CA SKI", aki)
        else:
            _add_check_item(report, "Relationship", "warn", "AKI differs from CA SKI", f"Certificate AKI: {aki}\nCA SKI: {ski}")
    else:
        _add_check_item(report, "Relationship", "info", "AKI/SKI comparison skipped", "Certificate AKI or CA SKI is missing.")

    serial_hex = format(cert.serial_number, "x")
    _add_check_item(report, "Certificate details", "info", "Certificate serial", serial_hex)

    report["headline"] = "This CA appears to have issued the certificate." if issued else "This CA did not issue the certificate."
    if issued:
        _add_relationship(report, "certificate", "ca", "pass", "Issued by this CA", "Issuer, signature, and CA constraints all line up.")
    else:
        _add_relationship(report, "certificate", "ca", "fail", "Not issued by this CA", "Issuer name, signature verification, or CA constraints failed.")
    return _finalize_report(report)


def _build_object_key_report(slots):
    report = _new_check_report(
        "object_key",
        "Certificate or CSR vs Key",
        "Check whether a public or private key matches the CSR or certificate."
    )
    object_kind, obj = _parse_object_slot(report, slots["primary"], "Certificate or CSR")
    key_kind, key_obj = _parse_key_slot(report, slots["secondary"], "Key")
    if not (obj and key_obj):
        report["headline"] = "Unable to determine whether the key matches."
        return _finalize_report(report)

    object_public_key = obj.public_key()
    comparison_key = key_obj.public_key() if key_kind == "private_key" else key_obj
    object_label = "CSR" if object_kind == "csr" else "Certificate"
    key_label = "Private key" if key_kind == "private_key" else "Public key"
    object_entity_id = "csr" if object_kind == "csr" else "certificate"
    key_entity_id = "private_key" if key_kind == "private_key" else "public_key"

    _add_entity(report, object_entity_id, object_label, _name_string(obj.subject), object_kind, "primary", "info")
    _add_entity(report, key_entity_id, key_label, _summarize_public_key(comparison_key), key_kind, "secondary", "info")

    if _public_key_match(object_public_key, comparison_key):
        _add_check_item(report, "Relationship", "pass", "Public keys match", f"The {key_label.lower()} matches the {object_label.lower()}.")
        report["headline"] = f"The {key_label.lower()} was used to make this {object_label.lower()}."
        _add_relationship(report, object_entity_id, key_entity_id, "pass", f"Made with this {key_label.lower()}", "The public key material matches.")
    else:
        _add_check_item(report, "Relationship", "fail", "Public keys differ", f"The {key_label.lower()} does not match the {object_label.lower()}.")
        report["headline"] = f"The {key_label.lower()} was not used to make this {object_label.lower()}."
        _add_relationship(report, object_entity_id, key_entity_id, "fail", f"Not made with this {key_label.lower()}", "The public key material does not match.")

    object_fp = _digest_hex(_public_key_bytes(object_public_key))
    key_fp = _digest_hex(_public_key_bytes(comparison_key))
    _add_check_item(report, "Fingerprints", "info", "Public key SHA-256", f"{object_label}: {object_fp}\n{key_label}: {key_fp}")
    _add_check_item(report, "Fingerprints", "info", "Algorithms", f"{object_label}: {_summarize_public_key(object_public_key)}\n{key_label}: {_summarize_public_key(comparison_key)}")
    return _finalize_report(report)


def _merge_report_into(target, source, category_prefix=None):
    existing_slots = {item.get("slot") for item in target.get("inputs", [])}
    for input_item in source.get("inputs", []):
        if input_item.get("slot") in existing_slots:
            continue
        target["inputs"].append(input_item)
        existing_slots.add(input_item.get("slot"))
    existing_entities = {item.get("id") for item in target.get("entities", [])}
    for entity in source.get("entities", []):
        if entity.get("id") in existing_entities:
            continue
        target["entities"].append(entity)
        existing_entities.add(entity.get("id"))
    for relationship in source.get("relationships", []):
        target["relationships"].append(relationship)
    for category, checks in source.get("categories", {}).items():
        merged_category = f"{category_prefix}: {category}" if category_prefix else category
        for check in checks:
            _add_check_item(target, merged_category, check["status"], check["label"], check["details"])


def _build_csr_certificate_ca_report(slots):
    report = _new_check_report(
        "csr_certificate_ca",
        "CSR + Certificate + CA",
        "Run request matching and issuer verification in one pass."
    )
    csr_cert_report = _build_csr_certificate_report({
        "primary": slots["primary"],
        "secondary": slots["secondary"],
        "tertiary": slots["tertiary"],
    })
    ca_cert_report = _build_ca_certificate_report({
        "primary": slots["tertiary"],
        "secondary": slots["secondary"],
        "tertiary": slots["primary"],
    })
    _merge_report_into(report, csr_cert_report, "Request match")
    _merge_report_into(report, ca_cert_report, "Issuer check")

    if report["counts"]["fail"]:
        report["headline"] = "At least one part of the CSR, certificate, and CA chain check failed."
    elif report["counts"]["warn"]:
        report["headline"] = "The chain mostly lines up, with some differences worth reviewing."
    else:
        report["headline"] = "The CSR, certificate, and CA all line up cleanly."
    return _finalize_report(report)


def _build_certificate_key_ca_report(slots):
    report = _new_check_report(
        "certificate_key_ca",
        "Certificate vs Key vs CA",
        "Run certificate-to-key matching and CA issuer verification in one pass."
    )
    cert_key_report = _build_object_key_report({
        "primary": slots["primary"],
        "secondary": slots["secondary"],
        "tertiary": slots["tertiary"],
    })
    ca_cert_report = _build_ca_certificate_report({
        "primary": slots["tertiary"],
        "secondary": slots["primary"],
        "tertiary": slots["secondary"],
    })
    _merge_report_into(report, cert_key_report, "Analysis")
    _merge_report_into(report, ca_cert_report, "Analysis")

    if report["counts"]["fail"]:
        report["headline"] = "One or more certificate relationships failed."
    elif report["counts"]["warn"]:
        report["headline"] = "The certificate relationships mostly line up, with some differences."
    else:
        report["headline"] = "The certificate matches both the key and the CA."
    return _finalize_report(report)


def _scenario_label(mode):
    labels = {
        "auto": "Auto detect from provided files",
        "csr_certificate": "CSR vs Certificate",
        "ca_certificate": "CA vs Certificate",
        "object_key": "Certificate or CSR vs Key",
        "csr_certificate_ca": "CSR vs Certificate vs CA",
        "certificate_key_ca": "Certificate vs Key vs CA",
    }
    return labels.get(mode, mode or "Unknown")


def _looks_like_ca_certificate(cert):
    bc = _basic_constraints_summary(cert)
    return bool(bc and bc["ca"])


def _can_issue(candidate_ca, candidate_leaf):
    try:
        _verify_cert_signature(candidate_leaf, candidate_ca)
        return True
    except Exception:
        return False


def _infer_certificate_roles(cert_a, cert_b):
    a_is_ca = _looks_like_ca_certificate(cert_a)
    b_is_ca = _looks_like_ca_certificate(cert_b)

    if a_is_ca and not b_is_ca:
        return cert_a, cert_b
    if b_is_ca and not a_is_ca:
        return cert_b, cert_a

    if _name_string(cert_b.issuer) == _name_string(cert_a.subject) and _can_issue(cert_a, cert_b):
        return cert_a, cert_b
    if _name_string(cert_a.issuer) == _name_string(cert_b.subject) and _can_issue(cert_b, cert_a):
        return cert_b, cert_a

    if a_is_ca:
        return cert_a, cert_b
    if b_is_ca:
        return cert_b, cert_a
    return None, None


def _build_auto_detect_report(slots):
    parsed = []
    report = _new_check_report(
        "auto",
        "Auto-detected Check",
        "The app inferred the comparison scenario from the provided files."
    )

    for slot_name in ("primary", "secondary", "tertiary"):
        slot = slots[slot_name]
        if not _slot_has_value(slot):
            continue
        try:
            parsed_item = _detect_slot_object(slot)
            parsed.append(parsed_item)
            detail = f"Detected {parsed_item['label'].lower()}"
            obj = parsed_item["object"]
            if hasattr(obj, "subject"):
                detail += f"\n{_name_string(obj.subject)}"
            elif parsed_item["kind"] in ("private_key", "public_key"):
                key_obj = obj.public_key() if parsed_item["kind"] == "private_key" else obj
                detail += f"\n{_summarize_public_key(key_obj)}"
            _add_input_summary(report, slot_name, "Auto input", parsed_item["label"], "pass", detail)
            _add_check_item(report, "Inputs", "pass", f"{parsed_item['label']} parsed", parsed_item["filename"] or parsed_item["source"])
            if parsed_item["kind"] == "csr":
                _add_entity(report, f"auto-{slot_name}", "CSR", _name_string(parsed_item["object"].subject), "csr", slot_name, "info")
            elif parsed_item["kind"] == "certificate":
                cert_kind = "ca_certificate" if _looks_like_ca_certificate(parsed_item["object"]) else "certificate"
                title = "CA Certificate" if cert_kind == "ca_certificate" else "Certificate"
                _add_entity(report, f"auto-{slot_name}", title, _name_string(parsed_item["object"].subject), cert_kind, slot_name, "info")
            else:
                key_obj = parsed_item["object"].public_key() if parsed_item["kind"] == "private_key" else parsed_item["object"]
                title = "Private Key" if parsed_item["kind"] == "private_key" else "Public Key"
                _add_entity(report, f"auto-{slot_name}", title, _summarize_public_key(key_obj), parsed_item["kind"], slot_name, "info")
        except Exception as exc:
            _add_input_summary(report, slot_name, "Auto input", "Unknown", "fail", str(exc))
            _add_check_item(report, "Inputs", "fail", f"Input parse failed for {slot_name}", str(exc))

    if report["counts"]["fail"]:
        report["headline"] = "One or more files could not be parsed."
        return _finalize_report(report)

    csrs = [item for item in parsed if item["kind"] == "csr"]
    certs = [item for item in parsed if item["kind"] == "certificate"]
    keys = [item for item in parsed if item["kind"] in ("private_key", "public_key")]

    inferred_mode = None
    inferred_slots = None

    if len(csrs) == 1 and len(certs) == 1 and len(keys) == 0 and len(parsed) == 2:
        inferred_mode = "csr_certificate"
        inferred_slots = {"primary": slots[csrs[0]["slot"]], "secondary": slots[certs[0]["slot"]], "tertiary": {"slot": "tertiary", "bytes": b""}}
    elif len(certs) == 2 and len(csrs) == 0 and len(keys) == 0 and len(parsed) == 2:
        ca_item, leaf_item = _infer_certificate_roles(certs[0]["object"], certs[1]["object"])
        if ca_item is not None:
            ca_slot = certs[0]["slot"] if certs[0]["object"] is ca_item else certs[1]["slot"]
            leaf_slot = certs[0]["slot"] if certs[0]["object"] is leaf_item else certs[1]["slot"]
            inferred_mode = "ca_certificate"
            inferred_slots = {"primary": slots[ca_slot], "secondary": slots[leaf_slot], "tertiary": {"slot": "tertiary", "bytes": b""}}
    elif len(keys) == 1 and len(parsed) == 2 and len(csrs) + len(certs) == 1:
        obj_item = (csrs + certs)[0]
        inferred_mode = "object_key"
        inferred_slots = {"primary": slots[obj_item["slot"]], "secondary": slots[keys[0]["slot"]], "tertiary": {"slot": "tertiary", "bytes": b""}}
    elif len(csrs) == 1 and len(certs) == 2 and len(keys) == 0 and len(parsed) == 3:
        ca_obj, leaf_obj = _infer_certificate_roles(certs[0]["object"], certs[1]["object"])
        if ca_obj is not None:
            ca_slot = certs[0]["slot"] if certs[0]["object"] is ca_obj else certs[1]["slot"]
            leaf_slot = certs[0]["slot"] if certs[0]["object"] is leaf_obj else certs[1]["slot"]
            inferred_mode = "csr_certificate_ca"
            inferred_slots = {"primary": slots[csrs[0]["slot"]], "secondary": slots[leaf_slot], "tertiary": slots[ca_slot]}
    elif len(certs) == 2 and len(keys) == 1 and len(csrs) == 0 and len(parsed) == 3:
        ca_obj, leaf_obj = _infer_certificate_roles(certs[0]["object"], certs[1]["object"])
        if ca_obj is not None:
            ca_slot = certs[0]["slot"] if certs[0]["object"] is ca_obj else certs[1]["slot"]
            leaf_slot = certs[0]["slot"] if certs[0]["object"] is leaf_obj else certs[1]["slot"]
            inferred_mode = "certificate_key_ca"
            inferred_slots = {"primary": slots[leaf_slot], "secondary": slots[keys[0]["slot"]], "tertiary": slots[ca_slot]}

    if inferred_mode and inferred_slots:
        _add_check_item(report, "Scenario", "info", "Scenario inferred", _scenario_label(inferred_mode))
        child_report = build_check_report(
            inferred_mode,
            primary_text=inferred_slots["primary"].get("text", ""),
            primary_upload_bytes=inferred_slots["primary"].get("bytes"),
            primary_upload_name=inferred_slots["primary"].get("filename", ""),
            secondary_text=inferred_slots["secondary"].get("text", ""),
            secondary_upload_bytes=inferred_slots["secondary"].get("bytes"),
            secondary_upload_name=inferred_slots["secondary"].get("filename", ""),
            tertiary_text=inferred_slots["tertiary"].get("text", ""),
            tertiary_upload_bytes=inferred_slots["tertiary"].get("bytes"),
            tertiary_upload_name=inferred_slots["tertiary"].get("filename", ""),
        )
        _merge_report_into(report, child_report, "Analysis")
        report["title"] = child_report["title"]
        report["headline"] = child_report["headline"]
        report["headline_status"] = child_report["headline_status"]
        return _finalize_report(report)

    _add_check_item(
        report,
        "Scenario",
        "fail",
        "Scenario inference failed",
        "Supported automatic combinations are CSR + certificate, CA + certificate, certificate/CSR + key, CSR + certificate + CA, and certificate + key + CA."
    )
    report["headline"] = "The app could not infer a supported check scenario from the provided files."
    return _finalize_report(report)


def build_check_report(check_mode, primary_text="", primary_upload_bytes=None, primary_upload_name="",
                       secondary_text="", secondary_upload_bytes=None, secondary_upload_name="",
                       tertiary_text="", tertiary_upload_bytes=None, tertiary_upload_name=""):
    slots = {
        "primary": _prepare_input_slot("primary", primary_text, primary_upload_bytes, primary_upload_name),
        "secondary": _prepare_input_slot("secondary", secondary_text, secondary_upload_bytes, secondary_upload_name),
        "tertiary": _prepare_input_slot("tertiary", tertiary_text, tertiary_upload_bytes, tertiary_upload_name),
    }

    if check_mode == "auto":
        return _build_auto_detect_report(slots)
    if check_mode == "csr_certificate":
        return _build_csr_certificate_report(slots)
    if check_mode == "ca_certificate":
        return _build_ca_certificate_report(slots)
    if check_mode == "object_key":
        return _build_object_key_report(slots)
    if check_mode == "csr_certificate_ca":
        return _build_csr_certificate_ca_report(slots)
    if check_mode == "certificate_key_ca":
        return _build_certificate_key_ca_report(slots)

    report = _new_check_report("unknown", "Unknown check", "Select a supported check mode.")
    _add_check_item(report, "Inputs", "fail", "Unsupported check mode", check_mode or "No check mode selected.")
    report["headline"] = "No supported comparison mode was selected."
    return _finalize_report(report)
