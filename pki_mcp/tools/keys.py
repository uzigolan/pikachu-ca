"""Key management tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def key_list(
        page: int = 1,
        per_page: int = 25,
        search: str = "",
        key_type: str = "",
        curve_name: str = "",
        pqc_alg: str = "",
        date_from: str = "",
        date_to: str = "",
        sort_by: str = "id",
        sort_order: str = "desc",
    ) -> str:
        """List cryptographic keys with optional filtering and sorting.

        search: partial match on key name, curve name, or PQC algorithm.
        key_type: RSA | EC | PQC
        curve_name: EC curve partial match (e.g. prime256v1, secp384r1, secp521r1).
        pqc_alg: PQC algorithm partial match (e.g. mldsa44, mldsa65, mldsa87).
        date_from / date_to: ISO date strings filtering on created_at.
        sort_by: id | name | key_type | key_size | created_at
        sort_order: asc | desc (default desc)

        Returns paginated results with id, name, key_type, size/curve, and creation date."""
        result = await client.get("/api/v1/keys", params={
            "page": page, "per_page": per_page, "q": search,
            "key_type": key_type, "curve_name": curve_name, "pqc_alg": pqc_alg,
            "date_from": date_from, "date_to": date_to,
            "sort_by": sort_by, "sort_order": sort_order,
        })
        return fmt(result)

    @mcp.tool()
    async def key_generate(
        name: str,
        key_type: str = "EC",
        key_size: int = 2048,
        curve_name: str = "prime256v1",
        pqc_alg: str = "mldsa44",
    ) -> str:
        """Generate a new cryptographic key and store it on the server.

        key_type: RSA | EC | PQC
        key_size: RSA key size in bits (2048, 3072, 4096).  Ignored for EC/PQC.
        curve_name: EC curve (prime256v1, secp384r1, secp521r1).  Ignored for RSA/PQC.
        pqc_alg: PQC algorithm (mldsa44, mldsa65, mldsa87).  Requires Enterprise + oqsprovider.

        Returns the key id and public key PEM."""
        payload = {
            "name": name,
            "key_type": key_type.upper(),
            "key_size": key_size,
            "curve_name": curve_name,
            "pqc_alg": pqc_alg,
        }
        result = await client.post("/api/v1/keys", payload)
        return fmt(result)

    @mcp.tool()
    async def key_get(key_id: int, include_private: bool = False) -> str:
        """Get details of a stored key by ID.
        Set include_private=true to also retrieve the private key PEM (use with caution)."""
        result = await client.get(f"/api/v1/keys/{key_id}",
                                  params={"include_private": str(include_private).lower()})
        return fmt(result)

    @mcp.tool()
    async def key_delete(key_id: int) -> str:
        """Delete a stored key by ID. This is irreversible."""
        result = await client.delete(f"/api/v1/keys/{key_id}")
        return fmt(result)
