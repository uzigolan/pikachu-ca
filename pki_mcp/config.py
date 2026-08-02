"""
Configuration for the PKI MCP server.

All settings are read from environment variables (or a .env file).

Required:
    PKI_BASE_URL   – Base URL of the PKI server, e.g. https://localhost:5443

Not configured here (supplied per-request by clients):
    PKI_TOKEN is NOT set on the server.  Each HTTP client must send its own
    PKI API token in the X-PKI-Token request header.  This allows per-client
    attribution in the PKI server audit log.  Requests without X-PKI-Token
    are rejected with 401.

Optional:
    PKI_VERIFY_SSL – Set to "false" to disable SSL cert verification (self-signed certs).
                     Or provide a path to a CA bundle PEM.  Default: true
    MCP_TRANSPORT  – "stdio" (default) or "http"
    MCP_HOST       – Host for HTTP transport.  Default: 0.0.0.0
    MCP_PORT       – Port for HTTP transport.  Default: 8080
    MCP_NAME       – Display name for the MCP server.  Default: PKI Squire MCP
"""

from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    PKI_BASE_URL: str = "https://localhost:443"
    # PKI_TOKEN is intentionally absent: each HTTP client supplies its own via X-PKI-Token.
    # Accept "true"/"false" string or a path to a CA bundle
    PKI_VERIFY_SSL: str = "true"
    MCP_TRANSPORT: str = "stdio"
    MCP_HOST: str = "0.0.0.0"
    MCP_PORT: int = 8080
    MCP_NAME: str = "PKI Squire MCP"

    # HTTP server auth (Bearer tokens clients must send; empty = no auth check)
    MCP_AUTH_TOKEN: str = ""        # read-write token
    MCP_READONLY_TOKEN: str = ""    # read-only token (same tool access for now)

    # HTTP server TLS (leave empty for plain http://)
    MCP_SSL_CERTFILE: str = ""      # path to TLS certificate PEM
    MCP_SSL_KEYFILE: str = ""       # path to TLS private key PEM

    @field_validator("PKI_BASE_URL")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    def ssl_verify(self) -> bool | str:
        """Return the ssl verify value for httpx: bool or path string."""
        v = self.PKI_VERIFY_SSL.strip().lower()
        if v in ("false", "0", "no"):
            return False
        if v in ("true", "1", "yes"):
            return True
        # Treat as path to CA bundle
        return self.PKI_VERIFY_SSL


settings = Settings()
