"""Meta / versioning tools: pki_list_versions, pki_check_skill_version."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient, fmt
from ..version import SERVER_VERSION, SKILL_NAME, SKILL_VERSION


def register(mcp: FastMCP, client: PKIClient) -> None:

    @mcp.tool()
    async def pki_list_versions() -> str:
        """Return the pki-mcp server version and the skill version baked into this server build.

        Use this to check for drift between the loaded skill file (on the client)
        and the server's copy. Compare the returned skill version against the
        'version:' line in the loaded rad-pki-operations SKILL.md."""
        return fmt({
            "server": SERVER_VERSION,
            "skills": [
                {"name": SKILL_NAME, "version": SKILL_VERSION}
            ],
        })

    @mcp.tool()
    async def pki_check_skill_version(skill: str, version: str) -> str:
        """Check whether the loaded skill version matches the server's copy.

        skill:   skill name, e.g. "rad-pki-operations"
        version: version string from the loaded SKILL.md, e.g. "1.0.0"

        Returns {"ok": true} when they match, or {"alerts": [...]} with drift messages."""
        alerts = []

        if skill != SKILL_NAME:
            alerts.append(
                f"Unknown skill '{skill}'. This server only knows '{SKILL_NAME}'."
            )
        elif version != SKILL_VERSION:
            alerts.append(
                f"VERSION MISMATCH — loaded skill is {version} but server has "
                f"{SKILL_VERSION}. Re-run the installer to sync the skill file."
            )

        if alerts:
            return fmt({"ok": False, "alerts": alerts})
        return fmt({"ok": True, "skill": skill, "version": version})

    @mcp.tool()
    async def list_filter_capabilities(resource: str = "") -> str:
        """Return the full filtering, sorting, and pagination capabilities for PKI list tools.

        resource: optional — certificates | keys | csrs | users | events
        If omitted, returns capabilities for ALL resources.

        Use this whenever the user asks 'how can I filter ...', 'what can I search by',
        'how do I sort ...', or 'what filters are available'."""
        caps = {
            "certificates": {
                "tool": "certificate_list",
                "filters": {
                    "search": "Partial match on subject, serial, or common_name",
                    "status": "valid | revoked | expired",
                    "date_from": "ISO date (e.g. 2026-07-01) — filters on issuance date (not_valid_before)",
                    "date_to": "ISO date — upper bound on issuance date (not_valid_before)",
                    "issued_via": "ui | scep | est | api",
                    "username": "Partial match on the issuing user's username",
                },
                "sort_by": ["id", "common_name", "serial", "not_valid_before", "not_valid_after", "issued_via", "username"],
                "sort_order": "asc | desc (default: desc)",
                "pagination": "page, per_page (max 200)",
            },
            "keys": {
                "tool": "key_list",
                "filters": {
                    "search": "Partial match on key name, curve name, or PQC algorithm",
                    "key_type": "RSA | EC | PQC",
                    "curve_name": "EC curve partial match (e.g. prime256v1, secp384r1, secp521r1)",
                    "pqc_alg": "PQC algorithm partial match (e.g. mldsa44, mldsa65, mldsa87)",
                    "date_from": "ISO date — lower bound on created_at",
                    "date_to": "ISO date — upper bound on created_at",
                },
                "sort_by": ["id", "name", "key_type", "key_size", "created_at"],
                "sort_order": "asc | desc (default: desc)",
                "pagination": "page, per_page (max 200)",
            },
            "csrs": {
                "tool": "csr_list",
                "filters": {
                    "search": "Partial match on CSR name",
                    "source": "generated | imported | scep | est",
                    "date_from": "ISO date — lower bound on created_at",
                    "date_to": "ISO date — upper bound on created_at",
                },
                "sort_by": ["id", "name", "source", "created_at", "key_id", "profile_id"],
                "sort_order": "asc | desc (default: desc)",
                "pagination": "page, per_page (max 200)",
            },
            "users": {
                "tool": "user_list",
                "note": "[ADMIN] only",
                "filters": {
                    "search": "Partial match on username or email",
                    "role": "user | admin",
                    "status": "active | disabled | pending",
                },
                "sort_by": ["id", "username", "role", "status", "created_at", "last_login"],
                "sort_order": "asc | desc (default: asc)",
                "pagination": "page, per_page (max 200)",
            },
            "events": {
                "tool": "event_list",
                "filters": {
                    "search": "Partial match on resource name (quick name search)",
                    "resource_type": "certificate | key | csr | profile | ra_policy | user | challenge_password | psk",
                    "event_type": "create | delete | revoke | update | rotate",
                    "resource_name": "Explicit partial match on resource name / serial",
                    "date_from": "ISO date — lower bound on event timestamp",
                    "date_to": "ISO date — upper bound on event timestamp",
                },
                "sort_by": ["timestamp", "event_type", "resource_type", "resource_name"],
                "sort_order": "asc | desc (default: desc)",
                "pagination": "page, per_page (max 500)",
            },
        }

        resource = resource.lower().strip().rstrip("s")  # normalise: "certificate" == "certificates"
        lookup = {
            "certificate": "certificates", "key": "keys", "csr": "csrs",
            "user": "users", "event": "events",
        }
        key = lookup.get(resource, resource)
        if key in caps:
            return fmt({key: caps[key]})
        return fmt(caps)
