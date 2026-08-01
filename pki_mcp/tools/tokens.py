"""API token management tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def token_list() -> str:
        """List API tokens. Admins see all tokens; regular users see only their own."""
        result = await client.get("/api/v1/tokens")
        return fmt(result)

    @mcp.tool()
    async def token_create(
        name: str,
        validity: str = "60d",
        length: int = 64,
    ) -> str:
        """Create a new API token for the authenticated user.

        name: Human-readable label for the token.
        validity: Expiry duration, e.g. '30d', '12h', '6m', '1y'. Empty = no expiry.
        length: Token length in characters (24–256).

        IMPORTANT: The raw token is returned ONCE and cannot be retrieved again.
        Store it securely immediately."""
        payload = {"name": name, "validity": validity, "length": length}
        result = await client.post("/api/v1/tokens", payload)
        return fmt(result)

    @mcp.tool()
    async def token_delete(token_id: int) -> str:
        """Delete an API token by ID. Admins can delete any token; users can only delete their own."""
        result = await client.delete(f"/api/v1/tokens/{token_id}")
        return fmt(result)
