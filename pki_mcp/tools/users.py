"""User management tools (admin only)."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def user_list(
        page: int = 1,
        per_page: int = 25,
        search: str = "",
        role: str = "",
        status: str = "",
        sort_by: str = "username",
        sort_order: str = "asc",
    ) -> str:
        """[ADMIN] List users with optional filtering and sorting.

        search: partial match on username or email.
        role: user | admin
        status: active | disabled | pending
        sort_by: id | username | role | status | created_at | last_login
        sort_order: asc | desc (default asc)

        Returns paginated results."""
        result = await client.get("/api/v1/users", params={
            "page": page, "per_page": per_page, "q": search,
            "role": role, "status": status,
            "sort_by": sort_by, "sort_order": sort_order,
        })
        return fmt(result)

    @mcp.tool()
    async def user_get(user_id: int) -> str:
        """[ADMIN] Get details of a user by ID."""
        result = await client.get(f"/api/v1/users/{user_id}")
        return fmt(result)

    @mcp.tool()
    async def user_create(
        username: str,
        password: str,
        role: str = "user",
        email: str = "",
    ) -> str:
        """[ADMIN] Create a new user account.
        role must be 'user' or 'admin'. The account is created in 'active' state."""
        payload = {"username": username, "password": password, "role": role, "email": email}
        result = await client.post("/api/v1/users", payload)
        return fmt(result)

    @mcp.tool()
    async def user_delete(user_id: int) -> str:
        """[ADMIN] Permanently delete a user account by ID. Cannot delete your own account."""
        result = await client.delete(f"/api/v1/users/{user_id}")
        return fmt(result)

    @mcp.tool()
    async def user_approve(user_id: int) -> str:
        """[ADMIN] Approve a pending user registration (set status to active)."""
        result = await client.post(f"/api/v1/users/{user_id}/approve")
        return fmt(result)

    @mcp.tool()
    async def user_toggle_active(user_id: int) -> str:
        """[ADMIN] Toggle a user's active/disabled status."""
        result = await client.post(f"/api/v1/users/{user_id}/toggle_active")
        return fmt(result)

    @mcp.tool()
    async def user_change_role(user_id: int, role: str) -> str:
        """[ADMIN] Change a user's role. role must be 'user' or 'admin'."""
        result = await client.post(f"/api/v1/users/{user_id}/change_role", {"role": role})
        return fmt(result)

    @mcp.tool()
    async def user_reset_password(user_id: int, password: str) -> str:
        """[ADMIN] Reset a user's password. Minimum 8 characters."""
        result = await client.post(f"/api/v1/users/{user_id}/reset_password", {"password": password})
        return fmt(result)
