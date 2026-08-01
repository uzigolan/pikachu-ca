"""CSR management tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def csr_list(
        page: int = 1,
        per_page: int = 25,
        search: str = "",
        source: str = "",
        date_from: str = "",
        date_to: str = "",
        sort_by: str = "id",
        sort_order: str = "desc",
    ) -> str:
        """List Certificate Signing Requests with optional filtering and sorting.

        search: partial match on CSR name.
        source: generated | imported | scep | est
        date_from / date_to: ISO date strings filtering on created_at.
        sort_by: id | name | source | created_at | key_id | profile_id
        sort_order: asc | desc (default desc)

        Returns paginated results."""
        result = await client.get("/api/v1/csrs", params={
            "page": page, "per_page": per_page, "q": search,
            "source": source, "date_from": date_from, "date_to": date_to,
            "sort_by": sort_by, "sort_order": sort_order,
        })
        return fmt(result)

    @mcp.tool()
    async def csr_generate(name: str, key_id: int, profile_id: int) -> str:
        """Generate a new CSR using a stored key and profile template.

        key_id: ID of the private key to use (see key_list).
        profile_id: ID of the certificate profile/template (see profile_list).
        Returns the CSR id and PEM text."""
        payload = {"name": name, "key_id": key_id, "profile_id": profile_id}
        result = await client.post("/api/v1/csrs/generate", payload)
        return fmt(result)

    @mcp.tool()
    async def csr_import(csr_pem: str, name: str = "") -> str:
        """Import an externally generated CSR (PEM format) into the server.
        name is optional; derived from the CSR's CN if not provided."""
        payload = {"csr_pem": csr_pem, "name": name}
        result = await client.post("/api/v1/csrs/import", payload)
        return fmt(result)

    @mcp.tool()
    async def csr_get(csr_id: int) -> str:
        """Get a stored CSR by ID, including its PEM text."""
        result = await client.get(f"/api/v1/csrs/{csr_id}")
        return fmt(result)

    @mcp.tool()
    async def csr_delete(csr_id: int) -> str:
        """Delete a stored CSR by ID."""
        result = await client.delete(f"/api/v1/csrs/{csr_id}")
        return fmt(result)
