"""EST and other enrollment protocol tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def est_cacerts() -> str:
        """Fetch the CA certificate chain via the EST /.well-known/est/cacerts endpoint.
        Returns the PKCS#7 response decoded as PEM text (base64)."""
        result = await client.get("/.well-known/est/cacerts")
        return fmt(result)

    @mcp.tool()
    async def est_enroll(csr_pem: str) -> str:
        """Submit a CSR for enrollment via the EST simpleenroll endpoint.

        csr_pem: DER-encoded CSR encoded as base64 (as per RFC 7030), or PEM.
        Returns the issued certificate as a PKCS#7 / PEM response.

        Note: The server may require a valid challenge password or mTLS depending
        on the RA policy configuration."""
        # EST expects base64-encoded DER; pass PEM and let the server normalise it
        result = await client.post("/.well-known/est/simpleenroll",
                                   {"csr": csr_pem})
        return fmt(result)
