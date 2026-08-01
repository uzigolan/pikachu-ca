"""Certificate tools."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def certificate_list(
        page: int = 1,
        per_page: int = 25,
        search: str = "",
        status: str = "",
        date_from: str = "",
        date_to: str = "",
        issued_via: str = "",
        username: str = "",
        sort_by: str = "id",
        sort_order: str = "desc",
    ) -> str:
        """List certificates with optional filtering and sorting.

        search: text search on subject, serial, or common_name.
        status: valid | revoked | expired
        date_from / date_to: ISO date strings (e.g. 2026-07-01) filtering on not_valid_before.
        issued_via: ui | scep | est | api
        username: filter by the issuing user (partial match).
        sort_by: id | common_name | serial | not_valid_before | not_valid_after | issued_via | username
        sort_order: asc | desc (default desc)

        Returns paginated results with id, serial, subject, validity, revoked, and expired fields."""
        result = await client.get("/api/v1/certificates", params={
            "page": page, "per_page": per_page, "q": search, "status": status,
            "date_from": date_from, "date_to": date_to,
            "issued_via": issued_via, "username": username,
            "sort_by": sort_by, "sort_order": sort_order,
        })
        return fmt(result)

    @mcp.tool()
    async def certificate_get(cert_id: int) -> str:
        """Get full details of a certificate by its database ID.
        Returns subject, issuer, serial, validity, extensions, and PEM text."""
        result = await client.get(f"/api/v1/certificates/{cert_id}")
        return fmt(result)

    @mcp.tool()
    async def certificate_sign(
        csr_pem: str = "",
        csr_id: int = 0,
        policy_id: int = 0,
        validity_days: int = 0,
        no_extensions: bool = False,
        use_csr_extensions: bool = False,
    ) -> str:
        """Sign a CSR and issue a certificate.

        Provide either csr_pem (raw PEM string) or csr_id (ID of a stored CSR).
        policy_id selects the RA policy (0 = server default).
        validity_days overrides the policy validity (0 = use policy default).
        no_extensions: sign without any extensions.
        use_csr_extensions: copy extensions from the CSR itself.

        Returns the issued certificate details including PEM and serial number."""
        payload: dict = {}
        if csr_pem:
            payload["csr_pem"] = csr_pem
        if csr_id:
            payload["csr_id"] = csr_id
        if policy_id:
            payload["policy_id"] = policy_id
        if validity_days:
            payload["validity_days"] = str(validity_days)
        if no_extensions:
            payload["no_extensions"] = True
        if use_csr_extensions:
            payload["use_csr_extensions"] = True
        result = await client.post("/api/v1/certificates/sign", payload)
        return fmt(result)

    @mcp.tool()
    async def certificate_revoke(cert_id: int) -> str:
        """Revoke a certificate by its database ID. Updates the CRL automatically."""
        result = await client.post(f"/api/v1/certificates/{cert_id}/revoke")
        return fmt(result)

    @mcp.tool()
    async def certificate_delete(cert_id: int) -> str:
        """Permanently delete a certificate record from the database by its ID."""
        result = await client.delete(f"/api/v1/certificates/{cert_id}")
        return fmt(result)

    @mcp.tool()
    async def certificate_download(cert_id: int) -> str:
        """Download/retrieve the PEM text of a certificate by its database ID."""
        result = await client.get(f"/api/v1/certificates/{cert_id}/download")
        return fmt(result)
