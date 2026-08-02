#!/usr/bin/env bash
# Install pki-mcp as a systemd service (HTTP transport).
#
# Usage (run as root or with sudo from the repo root):
#   sudo bash scripts/install/mcp_server/install-mcp-service.sh
#   sudo bash scripts/install/mcp_server/install-mcp-service.sh --reconfigure
#   sudo bash scripts/install/mcp_server/install-mcp-service.sh --root /opt/pki --user pki
#
# Interactive flow (3 sections):
#   Section 1 -- PKI CA server   : base URL, API token, SSL verify
#   Section 2 -- MCP HTTP server : bind host/port, TLS, client auth tokens
#   Section 3 -- Service install : Linux service user, install path
#
# Config is saved to .mcp-http.env in the repo root and reused on re-runs.
# On each run you are asked whether to keep the existing config or reconfigure.

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults (override via flags)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SERVICE_USER="pki"
SERVICE_NAME="pki-mcp"
UNIT_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
RECONFIGURE=false

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --root)         PKI_ROOT="$2";       shift 2 ;;
        --user)         SERVICE_USER="$2";   shift 2 ;;
        --reconfigure)  RECONFIGURE=true;    shift   ;;
        *)              echo "Unknown argument: $1"; exit 1 ;;
    esac
done

VENV_PYTHON="${PKI_ROOT}/pki_mcp/.venv/bin/python"
ENV_FILE="${PKI_ROOT}/.mcp-http.env"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
section() { echo ""; echo "  ┌─────────────────────────────────────────────────────┐"; printf "  │  %s\n" "$*"; echo "  └─────────────────────────────────────────────────────┘"; }
ask()     { local __var=$1 prompt=$2 default=${3:-}; local ans; read -r -p "  ${prompt}" ans; printf -v "$__var" '%s' "${ans:-$default}"; }
ask_secret() { local __var=$1 prompt=$2; local ans; read -r -s -p "  ${prompt}" ans; echo; printf -v "$__var" '%s' "$ans"; }
random_token() { "${VENV_PYTHON}" -c "import secrets; print(secrets.token_urlsafe(32))" 2>/dev/null; }
read_env_key() { local key=$1; grep -E "^${key}=" "${ENV_FILE}" 2>/dev/null | head -1 | cut -d= -f2- || true; }
write_env_file() {
    # Write associative-array contents to $ENV_FILE
    local -n _cfg=$1
    : > "${ENV_FILE}"
    for key in "${!_cfg[@]}"; do
        echo "${key}=${_cfg[$key]}" >> "${ENV_FILE}"
    done
    echo "  config -> ${ENV_FILE}"
}

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: this script must be run as root (use sudo)."
    exit 1
fi

# ---------------------------------------------------------------------------
# Venv check (must exist before we can generate tokens etc.)
# ---------------------------------------------------------------------------
if [[ ! -f "${VENV_PYTHON}" ]]; then
    echo "ERROR: venv not found at ${VENV_PYTHON}"
    echo "       Bootstrap it first:"
    echo "         cd ${PKI_ROOT}"
    echo "         python3 -m venv pki_mcp/.venv"
    echo "         pki_mcp/.venv/bin/pip install -q -r pki_mcp/requirements.txt"
    exit 1
fi

# ---------------------------------------------------------------------------
# Decide whether to reuse or recollect config
# ---------------------------------------------------------------------------
USE_SAVED=false
if [[ "${RECONFIGURE}" == false && -f "${ENV_FILE}" ]]; then
    echo ""
    echo "  Existing MCP HTTP server config found (${ENV_FILE}):"
    echo "    PKI_BASE_URL = $(read_env_key PKI_BASE_URL)"
    echo "    MCP_PORT     = $(read_env_key MCP_PORT)"
    _tls=$(read_env_key MCP_SSL_CERTFILE)
    echo "    TLS          = ${_tls:-(none)}"
    _rw=$(read_env_key MCP_AUTH_TOKEN)
    [[ -n "$_rw" ]] && echo "    RW token     = ${_rw:0:8}..."
    ask _keep "Keep existing config? [Y/n]: " "Y"
    [[ "$_keep" =~ ^[nN] ]] || USE_SAVED=true
fi

# ---------------------------------------------------------------------------
# Section 1 — PKI CA server
# ---------------------------------------------------------------------------
if [[ "${USE_SAVED}" == false ]]; then
    section "Section 1 of 3  --  Pikachu CA server"
    echo "  Base URL of the Flask PKI/CA server."
    echo "  (No server-side token needed: each client supplies its own via X-PKI-Token)"
    echo ""
    ask     PKI_BASE_URL  "PKI base URL [https://localhost:443]: "  "https://localhost:443"
    ask PKI_VERIFY_SSL "Verify PKI server TLS cert? [false]: " "false"

    # ---------------------------------------------------------------------------
    # Section 2 — MCP HTTP server settings
    # ---------------------------------------------------------------------------
    section "Section 2 of 3  --  MCP HTTP server"
    echo "  Bind address, TLS mode, and client Bearer tokens."
    echo ""
    ask MCP_HOST "Bind host [0.0.0.0]: "  "0.0.0.0"
    ask MCP_PORT "Bind port [8080]: "     "8080"

    echo ""
    echo "  TLS for the MCP HTTP server:"
    echo "    1) No TLS       -- plain http:// [default]"
    echo "    2) Self-signed  -- generate a new cert (localhost/127.0.0.1)"
    echo "    3) Import       -- provide paths to an existing cert + key"
    ask _tls_choice "Choice [1]: " "1"

    MCP_SSL_CERTFILE=""
    MCP_SSL_KEYFILE=""
    case "${_tls_choice}" in
        2|s*)
            CERT_DIR="${PKI_ROOT}/pki_mcp/certs"
            MCP_SSL_CERTFILE="${CERT_DIR}/mcp-cert.pem"
            MCP_SSL_KEYFILE="${CERT_DIR}/mcp-key.pem"
            mkdir -p "${CERT_DIR}"
            if command -v openssl &>/dev/null; then
                openssl req -x509 -newkey rsa:2048 \
                    -keyout "${MCP_SSL_KEYFILE}" -out "${MCP_SSL_CERTFILE}" \
                    -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
                echo "  cert -> ${MCP_SSL_CERTFILE} (openssl)"
            else
                "${VENV_PYTHON}" - <<'PYEOF'
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime, ipaddress, pathlib, os, sys
cert_dir = os.environ.get('CERT_DIR', '.')
key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
cert = (
    x509.CertificateBuilder()
    .subject_name(subj).issuer_name(subj)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.UTC))
    .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([
        x509.DNSName('localhost'),
        x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
    ]), critical=False)
    .sign(key, hashes.SHA256())
)
pathlib.Path(cert_dir, 'mcp-key.pem').write_bytes(
    key.private_bytes(serialization.Encoding.PEM,
                      serialization.PrivateFormat.TraditionalOpenSSL,
                      serialization.NoEncryption()))
pathlib.Path(cert_dir, 'mcp-cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
print('cert -> ' + cert_dir + '/mcp-cert.pem (python cryptography)')
PYEOF
            fi
            ;;
        3|i*)
            ask MCP_SSL_CERTFILE "Certificate file path (PEM): " ""
            ask MCP_SSL_KEYFILE  "Private key file path  (PEM): " ""
            ;;
    esac

    echo ""
    echo "  Client Bearer tokens  (press Enter to auto-generate a secure random token):"
    ask _rw "Read-Write token [auto-generate]: " ""
    if [[ -z "${_rw}" ]]; then _rw=$(random_token); echo "  Generated RW: ${_rw}"; fi
    MCP_AUTH_TOKEN="${_rw}"

    ask _ro "Read-Only  token [auto-generate]: " ""
    if [[ -z "${_ro}" ]]; then _ro=$(random_token); echo "  Generated RO: ${_ro}"; fi
    MCP_READONLY_TOKEN="${_ro}"

    # ---------------------------------------------------------------------------
    # Section 3 — Service install
    # ---------------------------------------------------------------------------
    section "Section 3 of 3  --  Service install"
    echo "  Linux user and install path for the systemd service."
    echo ""
    ask SERVICE_USER  "Service user  [${SERVICE_USER}]: "  "${SERVICE_USER}"
    ask PKI_ROOT      "Install root  [${PKI_ROOT}]: "       "${PKI_ROOT}"

    # Write collected config to .mcp-http.env
    # Use ordered output so the file is readable
    {
        echo "PKI_BASE_URL=${PKI_BASE_URL}"
        echo "PKI_VERIFY_SSL=${PKI_VERIFY_SSL}"
        echo "MCP_HOST=${MCP_HOST}"
        echo "MCP_PORT=${MCP_PORT}"
        echo "MCP_AUTH_TOKEN=${MCP_AUTH_TOKEN}"
        echo "MCP_READONLY_TOKEN=${MCP_READONLY_TOKEN}"
        [[ -n "${MCP_SSL_CERTFILE}" ]] && echo "MCP_SSL_CERTFILE=${MCP_SSL_CERTFILE}"
        [[ -n "${MCP_SSL_KEYFILE}"  ]] && echo "MCP_SSL_KEYFILE=${MCP_SSL_KEYFILE}"
    } > "${ENV_FILE}"
    echo "  config -> ${ENV_FILE}"

    # Show client config snippet
    _scheme="http"
    [[ -n "${MCP_SSL_CERTFILE}" ]] && _scheme="https"
    _mcp_url="${_scheme}://localhost:${MCP_PORT}/mcp"
    echo ""
    echo "  ----------------------------------------------------------------"
    echo "  MCP HTTP client configuration:"
    echo "    URL     : ${_mcp_url}"
    echo "    RW token: ${MCP_AUTH_TOKEN}"
    echo "    RO token: ${MCP_READONLY_TOKEN}"
    echo ""
    echo "  VS Code mcp.json:"
    echo '    "pki-mcp": {'
    echo '      "type": "http",'
    echo "      \"url\": \"${_mcp_url}\","
    echo '      "headers": {'
    echo "        \"Authorization\": \"Bearer ${MCP_AUTH_TOKEN}\","
    echo '        "X-PKI-Token": "<your-personal-pki-api-token>"  // REQUIRED'
    echo '      }'
    echo '    }'
    echo "  (each client must set X-PKI-Token to their own PKI API token)"
    echo "  ----------------------------------------------------------------"
else
    # Load saved values so variables are populated for section 3
    PKI_BASE_URL=$(read_env_key PKI_BASE_URL)
    MCP_HOST=$(read_env_key MCP_HOST)
    MCP_PORT=$(read_env_key MCP_PORT)
    MCP_SSL_CERTFILE=$(read_env_key MCP_SSL_CERTFILE)

    section "Section 3 of 3  --  Service install"
    echo "  Linux user and install path for the systemd service."
    echo ""
    ask SERVICE_USER  "Service user  [${SERVICE_USER}]: "  "${SERVICE_USER}"
    ask PKI_ROOT      "Install root  [${PKI_ROOT}]: "       "${PKI_ROOT}"
fi

# Recompute venv path in case PKI_ROOT was changed in section 3
VENV_PYTHON="${PKI_ROOT}/pki_mcp/.venv/bin/python"

# ---------------------------------------------------------------------------
# Ensure service user exists
# ---------------------------------------------------------------------------
if ! id -u "${SERVICE_USER}" &>/dev/null; then
    echo "Creating system user '${SERVICE_USER}' ..."
    useradd --system --no-create-home --shell /sbin/nologin "${SERVICE_USER}"
fi

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${PKI_ROOT}" 2>/dev/null || true
# Protect the token file from other users
chmod 600 "${ENV_FILE}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Write systemd unit (substitute actual paths into template)
# ---------------------------------------------------------------------------
echo ""
echo "Writing ${UNIT_DEST} ..."
sed \
    -e "s|/opt/pki|${PKI_ROOT}|g" \
    -e "s|User=pki|User=${SERVICE_USER}|g" \
    -e "s|Group=pki|Group=${SERVICE_USER}|g" \
    "${SCRIPT_DIR}/pki-mcp.service" > "${UNIT_DEST}"
chmod 644 "${UNIT_DEST}"

# ---------------------------------------------------------------------------
# Enable and start
# ---------------------------------------------------------------------------
echo "Reloading systemd ..."
systemctl daemon-reload

echo "Enabling ${SERVICE_NAME} (auto-start on boot) ..."
systemctl enable "${SERVICE_NAME}"

echo "Starting ${SERVICE_NAME} ..."
systemctl restart "${SERVICE_NAME}"

sleep 2
systemctl status "${SERVICE_NAME}" --no-pager || true

echo ""
echo "Done. Useful commands:"
echo "  sudo systemctl status  ${SERVICE_NAME}"
echo "  sudo systemctl restart ${SERVICE_NAME}"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo "  sudo systemctl disable ${SERVICE_NAME}   # remove from auto-start"
echo "  sudo systemctl stop    ${SERVICE_NAME}   # stop now"
