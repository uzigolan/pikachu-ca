"""Audit event tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def event_list(
        page: int = 1,
        per_page: int = 50,
        search: str = "",
        resource_type: str = "",
        event_type: str = "",
        resource_name: str = "",
        date_from: str = "",
        date_to: str = "",
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> str:
        """List audit log events with optional filters and sorting.

        search: partial match on resource name (quick name search).
        resource_type: certificate | key | csr | profile | ra_policy | user | challenge_password | psk
        event_type: create | delete | revoke | update | rotate
        resource_name: explicit partial match on the resource name / serial (same as search).
        date_from / date_to: ISO date strings (e.g. 2026-07-01) filtering on timestamp.
        sort_by: timestamp | event_type | resource_type | resource_name
        sort_order: asc | desc (default desc)"""
        result = await client.get("/api/v1/events", params={
            "page": page,
            "per_page": per_page,
            "q": search,
            "resource_type": resource_type,
            "event_type": event_type,
            "resource_name": resource_name,
            "date_from": date_from,
            "date_to": date_to,
            "sort_by": sort_by,
            "sort_order": sort_order,
        })
        return fmt(result)

    @mcp.tool()
    async def event_get(event_id: int) -> str:
        """Get the full details of a single audit event by ID."""
        result = await client.get(f"/api/v1/events/{event_id}")
        return fmt(result)
