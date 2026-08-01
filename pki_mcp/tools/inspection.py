"""PEM inspection tool."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def inspect_pem(pem: str) -> str:
        """Parse and inspect a PEM-encoded object (certificate, CSR, or public/private key).

        Automatically detects the type and returns structured details:
        - Certificate: subject, issuer, serial, validity, public key, extensions
        - CSR: subject, public key algorithm, requested extensions
        - Key: key type, size/curve, public key fingerprint

        pem: PEM string starting with -----BEGIN ..."""
        result = await client.post("/api/v1/inspect", {"pem": pem})
        return fmt(result)
