"""Challenge password tools (Enterprise, SCEP)."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def challenge_password_list(page: int = 1, per_page: int = 25) -> str:
        """List SCEP challenge passwords with their status (active/expired) and usage info."""
        result = await client.get("/challenge_passwords/data",
                                  params={"page": page, "per_page": per_page})
        return fmt(result)

    @mcp.tool()
    async def challenge_password_create(
        validity: str = "60m",
        usage_mode: str = "single_use",
        length: int = 16,
    ) -> str:
        """Create a new SCEP challenge password.

        validity: How long the password is valid, e.g. '60m', '24h', '7d'.
        usage_mode: 'single_use' | 'reusable' | 'unlimited'.
        length: Password character length (8–64).

        Returns the generated password value."""
        payload = {"validity": validity, "usage_mode": usage_mode, "length": length}
        result = await client.post("/api/challenge_passwords", payload)
        return fmt(result)

    @mcp.tool()
    async def challenge_password_delete(value: str) -> str:
        """Delete a specific challenge password by its value."""
        result = await client.post("/delete_challenge_password", {"value": value})
        return fmt(result)

    @mcp.tool()
    async def challenge_password_delete_expired(scope: str = "own") -> str:
        """Delete all expired challenge passwords.
        scope: 'own' (your passwords only) or 'all' (admin only — all users)."""
        result = await client.post("/delete_all_expired_challenge_passwords", {"scope": scope})
        return fmt(result)
