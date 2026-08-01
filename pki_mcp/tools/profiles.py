"""Certificate profile/template tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def profile_list() -> str:
        """List all certificate profiles (OpenSSL .cnf templates) on the server."""
        result = await client.get("/api/v1/profiles")
        return fmt(result)

    @mcp.tool()
    async def profile_get(profile_id: int) -> str:
        """Get a certificate profile by ID, including its full OpenSSL .cnf content."""
        result = await client.get(f"/api/v1/profiles/{profile_id}")
        return fmt(result)

    @mcp.tool()
    async def profile_create(
        name: str,
        content: str,
        profile_type: str = "",
        template_name: str = "",
    ) -> str:
        """Create a new certificate profile with an OpenSSL .cnf config block.

        name: Unique profile name.
        content: OpenSSL extension/CSR config block (INI-style, e.g. [req] / [v3_ext] sections).
        profile_type: Optional category label (e.g. 'server', 'client', 'ca').
        template_name: Optional Jinja2 template filename this was rendered from."""
        payload = {
            "name": name,
            "content": content,
            "profile_type": profile_type,
            "template_name": template_name or name,
        }
        result = await client.post("/api/v1/profiles", payload)
        return fmt(result)

    @mcp.tool()
    async def profile_update(
        profile_id: int,
        content: str = "",
        profile_type: str = "",
    ) -> str:
        """Update the content or type of an existing certificate profile."""
        payload = {}
        if content:
            payload["content"] = content
        if profile_type:
            payload["profile_type"] = profile_type
        result = await client.put(f"/api/v1/profiles/{profile_id}", payload)
        return fmt(result)

    @mcp.tool()
    async def profile_delete(profile_id: int) -> str:
        """Delete a certificate profile by ID."""
        result = await client.delete(f"/api/v1/profiles/{profile_id}")
        return fmt(result)
