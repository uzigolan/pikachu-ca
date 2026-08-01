"""Dashboard and statistics tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def dashboard_stats() -> str:
        """Get certificate counts: total, valid, expired, revoked.
        Also returns enrollment breakdown by source (UI / EST / SCEP / API)."""
        result = await client.get("/api/v1/dashboard")
        return fmt(result)

    @mcp.tool()
    async def dashboard_activity(limit: int = 200) -> str:
        """Get recent PKI activity events for charting or analysis.
        Returns the last N events (max 5000) with timestamps, types, and resource names."""
        result = await client.get("/api/v1/dashboard/activity", params={"limit": limit})
        return fmt(result)
