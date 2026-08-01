"""RA Policy tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def ra_policy_list() -> str:
        """List all RA (Registration Authority) enrollment policies.
        System policies are used as defaults; user policies are per-user overrides."""
        result = await client.get("/api/v1/ra_policies")
        return fmt(result)

    @mcp.tool()
    async def ra_policy_get(policy_id: int) -> str:
        """Get an RA policy by ID including its extension config and validity period."""
        result = await client.get(f"/api/v1/ra_policies/{policy_id}")
        return fmt(result)

    @mcp.tool()
    async def ra_policy_create(
        name: str,
        ext_config: str = "",
        validity_period: str = "365",
        is_system: bool = False,
        is_est_default: bool = False,
        is_scep_default: bool = False,
    ) -> str:
        """[ADMIN] Create a new RA enrollment policy.

        name: Policy name.
        ext_config: OpenSSL extension config block for certificate signing.
        validity_period: Certificate validity in days (e.g. '365', '730').
        is_system: Mark as system-wide default (replaces current system policy).
        is_est_default: Use as default for EST enrollment.
        is_scep_default: Use as default for SCEP enrollment."""
        payload = {
            "name": name,
            "ext_config": ext_config,
            "validity_period": validity_period,
            "is_system": is_system,
            "is_est_default": is_est_default,
            "is_scep_default": is_scep_default,
        }
        result = await client.post("/api/v1/ra_policies", payload)
        return fmt(result)

    @mcp.tool()
    async def ra_policy_update(
        policy_id: int,
        ext_config: str = "",
        validity_period: str = "",
        is_est_default: bool = False,
        is_scep_default: bool = False,
    ) -> str:
        """[ADMIN] Update an existing RA policy's extension config or validity period."""
        payload: dict = {}
        if ext_config:
            payload["ext_config"] = ext_config
        if validity_period:
            payload["validity_period"] = validity_period
        if is_est_default:
            payload["is_est_default"] = True
        if is_scep_default:
            payload["is_scep_default"] = True
        result = await client.put(f"/api/v1/ra_policies/{policy_id}", payload)
        return fmt(result)

    @mcp.tool()
    async def ra_policy_delete(policy_id: int) -> str:
        """[ADMIN] Delete an RA policy by ID."""
        result = await client.delete(f"/api/v1/ra_policies/{policy_id}")
        return fmt(result)
