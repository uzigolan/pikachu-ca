"""Register all MCP tools with the server."""
from __future__ import annotations

from mcp.server.mcpserver.server import MCPServer as FastMCP

from ..client import PKIClient
from .certificates import register as reg_certs
from .keys import register as reg_keys
from .csrs import register as reg_csrs
from .profiles import register as reg_profiles
from .ra_policies import register as reg_policies
from .users import register as reg_users
from .tokens import register as reg_tokens
from .challenge_passwords import register as reg_cp
from .psks import register as reg_psks
from .events import register as reg_events
from .dashboard import register as reg_dashboard
from .inspection import register as reg_inspect
from .ca import register as reg_ca
from .protocols import register as reg_protocols
from .meta import register as reg_meta


def register_all_tools(mcp: FastMCP, client: PKIClient) -> None:
    reg_certs(mcp, client)
    reg_keys(mcp, client)
    reg_csrs(mcp, client)
    reg_profiles(mcp, client)
    reg_policies(mcp, client)
    reg_users(mcp, client)
    reg_tokens(mcp, client)
    reg_cp(mcp, client)
    reg_psks(mcp, client)
    reg_events(mcp, client)
    reg_dashboard(mcp, client)
    reg_inspect(mcp, client)
    reg_ca(mcp, client)
    reg_protocols(mcp, client)
    reg_meta(mcp, client)
