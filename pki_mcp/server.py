"""
PKI Squire MCP Server entry point.

Usage:
    # stdio (for Claude Desktop / VS Code Copilot):
    PKI_BASE_URL=https://localhost:5443 python -m pki_mcp.server

    # HTTP (for remote / multi-client access):
    # No PKI_TOKEN on the server -- each client passes X-PKI-Token per request.
    PKI_BASE_URL=https://localhost:443 \\
        python -m pki_mcp.server --transport http --port 8080

    # Both transports via env:
    MCP_TRANSPORT=http MCP_PORT=8080 python -m pki_mcp.server
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from mcp.server.mcpserver.server import MCPServer as FastMCP

from .client import PKIClient, request_pki_token
from .config import settings
from .tools import register_all_tools


# ---------------------------------------------------------------------------
# Simple ASGI Bearer-auth wrapper (no Starlette dependency)
# ---------------------------------------------------------------------------

def _make_auth_middleware(app: Any, tokens: set[str]) -> Any:
    """Wrap *app* so that HTTP requests without a valid Bearer token get 401."""
    if not tokens:
        return app

    async def _middleware(scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            raw_headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
            auth = next(
                (v.decode("utf-8", errors="replace") for k, v in raw_headers
                 if k.lower() == b"authorization"),
                "",
            )
            token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
            if token not in tokens:
                body = b'{"error":"Unauthorized"}'
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(body)).encode()],
                    ],
                })
                await send({"type": "http.response.body", "body": body})
                return

            # Every client must supply its own PKI API token.
            pki_token = next(
                (v.decode("utf-8", errors="replace") for k, v in raw_headers
                 if k.lower() == b"x-pki-token"),
                "",
            )
            if not pki_token:
                body = b'{"error":"X-PKI-Token header is required"}'
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(body)).encode()],
                    ],
                })
                await send({"type": "http.response.body", "body": body})
                return

            reset_token = request_pki_token.set(pki_token)
            try:
                await app(scope, receive, send)
            finally:
                request_pki_token.reset(reset_token)
            return

        await app(scope, receive, send)

    return _middleware


def build_server() -> tuple[FastMCP, PKIClient]:
    # No shared PKI_TOKEN — every HTTP request must carry X-PKI-Token.
    mcp = FastMCP(settings.MCP_NAME)
    client = PKIClient(
        base_url=settings.PKI_BASE_URL,
        token="",
        verify_ssl=settings.ssl_verify(),
    )
    register_all_tools(mcp, client)
    return mcp, client


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PKI Squire MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=settings.MCP_TRANSPORT,
        help="MCP transport (default: %(default)s)",
    )
    parser.add_argument("--host", default=settings.MCP_HOST, help="HTTP bind host")
    parser.add_argument("--port", type=int, default=settings.MCP_PORT, help="HTTP port")
    parser.add_argument("--ssl-certfile", default=settings.MCP_SSL_CERTFILE or None,
                        help="TLS certificate PEM (enables HTTPS)")
    parser.add_argument("--ssl-keyfile", default=settings.MCP_SSL_KEYFILE or None,
                        help="TLS private key PEM")
    args = parser.parse_args()

    mcp, _ = build_server()

    if args.transport == "http":
        import anyio
        import uvicorn

        # Build the Starlette app so we can wrap it with auth middleware
        starlette_app = mcp.streamable_http_app(host=args.host)

        # Auth tokens: accept any non-empty token from env
        auth_tokens: set[str] = {
            t for t in (settings.MCP_AUTH_TOKEN, settings.MCP_READONLY_TOKEN) if t
        }
        asgi_app = _make_auth_middleware(starlette_app, auth_tokens)

        scheme = "https" if (args.ssl_certfile or args.ssl_keyfile) else "http"
        print(
            f"Starting PKI Squire MCP server (HTTP) on {args.host}:{args.port} ...\n"
            f"  Client URL   : {scheme}://<host>:{args.port}/mcp\n"
            f"  Auth         : {'token required' if auth_tokens else 'none (open)'}\n"
            f"  TLS          : {'yes (' + str(args.ssl_certfile) + ')' if args.ssl_certfile else 'no'}\n"
            f"  Attribution  : clients MUST send X-PKI-Token: <their-pki-api-token>",
            file=sys.stderr,
        )

        config = uvicorn.Config(
            asgi_app,
            host=args.host,
            port=args.port,
            log_level="info",
            ssl_certfile=args.ssl_certfile or None,
            ssl_keyfile=args.ssl_keyfile or None,
        )
        server = uvicorn.Server(config)
        anyio.run(server.serve)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
