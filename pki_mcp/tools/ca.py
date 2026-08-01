"""CA / VA / OCSP tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def ca_info() -> str:
        """Get information about the Sub-CA: subject, issuer, serial, validity, and CA mode (RSA/EC).
        Also returns the CA certificate PEM."""
        result = await client.get("/api/v1/ca")
        return fmt(result)

    @mcp.tool()
    async def va_info() -> str:
        """Get Validation Authority information: CRL file status, size, last modified,
        and count of revoked certificates in the database."""
        result = await client.get("/api/v1/va")
        return fmt(result)

    @mcp.tool()
    async def ocsp_check(serial_hex: str) -> str:
        """Check the OCSP revocation status of a certificate by its serial number (hex).

        Returns: 'good' (valid), 'revoked', or 'unknown'.
        Note: Queries the server's OCSP responder directly."""
        # Use the lightweight status endpoint for a quick DB-based lookup
        result = await client.get(f"/status/{serial_hex}")
        return fmt(result)

    @mcp.tool()
    async def config_get() -> str:
        """[ADMIN] Get a non-sensitive subset of the live server configuration
        (CA mode, SCEP enabled, editions, product name, etc.)."""
        result = await client.get("/api/v1/config")
        return fmt(result)

    @mcp.tool()
    async def logs_get(lines: int = 100) -> str:
        """[ADMIN] Retrieve the last N lines from the server log file (max 2000)."""
        result = await client.get("/api/v1/logs", params={"lines": lines})
        if isinstance(result, dict) and "lines" in result:
            return "\n".join(result["lines"])
        return fmt(result)
