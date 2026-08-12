"""Pre-shared key tools (Enterprise)."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def psk_list() -> str:
        """List all pre-shared keys with their status, rotation mode, and expiry info."""
        result = await client.get("/preshared_keys/data")
        return fmt(result)

    @mcp.tool()
    async def psk_get(name: str) -> str:
        """Retrieve the current value of a pre-shared key by name.
        The response includes the key's fingerprint (hash id), which can be used
        later with psk_get_by_hash to fetch this exact value even after rotation."""
        result = await client.get(f"/api/preshared_keys/{name}")
        return fmt(result)

    @mcp.tool()
    async def psk_history(name: str) -> str:
        """List the fingerprint (hash id) history of a pre-shared key:
        the current fingerprint plus rotated-out ones still kept in history."""
        result = await client.get(f"/api/preshared_keys/{name}/history")
        return fmt(result)

    @mcp.tool()
    async def psk_get_by_hash(name: str, hash_id: str) -> str:
        """Retrieve a specific value of a pre-shared key by its fingerprint (hash id).
        Works for the current value and for rotated-out values still kept in history."""
        result = await client.get(f"/api/preshared_keys/{name}/history/{hash_id}")
        return fmt(result)

    @mcp.tool()
    async def psk_create(
        name: str,
        length: int = 48,
        validity: str = "60d",
        rotation_interval: str = "",
        profile: str = "",
    ) -> str:
        """Create a new pre-shared key.

        name: Unique key name.
        length: Key length in bytes (4–256).
        validity: Expiry duration, e.g. '30d', '1y'. Empty = no expiry.
        rotation_interval: Auto-rotation interval, e.g. '7d'. Empty = no rotation.
        profile: Optional profile label (aes_128, aes_192, aes_256, NIST)."""
        payload = {
            "name": name,
            "length": length,
            "validity": validity,
            "rotation_interval": rotation_interval,
            "profile": profile,
        }
        result = await client.post("/api/preshared_keys", payload)
        return fmt(result)

    @mcp.tool()
    async def psk_delete(name: str) -> str:
        """Delete a pre-shared key by name."""
        result = await client.delete(f"/api/preshared_keys/{name}")
        return fmt(result)

    @mcp.tool()
    async def psk_start_rotation(name: str) -> str:
        """Start automatic rotation for a pre-shared key."""
        result = await client.post(f"/api/preshared_keys/{name}/rotation/start")
        return fmt(result)

    @mcp.tool()
    async def psk_stop_rotation(name: str) -> str:
        """Stop automatic rotation for a pre-shared key."""
        result = await client.post(f"/api/preshared_keys/{name}/rotation/stop")
        return fmt(result)

    @mcp.tool()
    async def psk_revoke(psk_id: int) -> str:
        """Revoke a pre-shared key by its database ID."""
        result = await client.post(f"/preshared_keys/{psk_id}/revoke")
        return fmt(result)

    @mcp.tool()
    async def psk_regenerate(psk_id: int) -> str:
        """Regenerate (rotate now) a pre-shared key by its database ID.
        Creates a new random value immediately, keeping the same name and settings."""
        result = await client.post(f"/preshared_keys/{psk_id}/regenerate")
        return fmt(result)
