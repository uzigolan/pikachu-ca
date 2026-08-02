"""
PKIClient – async HTTP client for the PKI Squire API.

All methods return a dict on success or {"error": "...", "status": N} on failure.
The caller (MCP tool) is responsible for formatting the response as a string.
"""

from __future__ import annotations

import contextvars
import json
from typing import Any

import httpx

# Set by the HTTP auth middleware when a client passes X-PKI-Token.
# Allows per-client attribution in the PKI server audit log.
request_pki_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_pki_token", default=None
)


class PKIError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class PKIClient:
    def __init__(self, base_url: str, token: str, verify_ssl: bool | str = True):
        self._base = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self._verify = verify_ssl
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers=self._headers,
            verify=verify_ssl,
            timeout=60.0,
            follow_redirects=True,
        )

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        override = request_pki_token.get()
        if override:
            # Per-request token overrides the shared server token for this call
            kwargs["headers"] = {**kwargs.get("headers", {}), "Authorization": f"Bearer {override}"}
        try:
            resp = await self._client.request(method, path, **kwargs)
        except httpx.RequestError as exc:
            return {"error": f"Connection error: {exc}", "status": 0}

        if resp.status_code == 204:
            return {"ok": True}

        ct = resp.headers.get("content-type", "")
        if "application/json" in ct:
            try:
                data = resp.json()
            except Exception:
                data = {"error": resp.text, "status": resp.status_code}
        else:
            data = {"data": resp.text, "status": resp.status_code}

        if resp.status_code >= 400:
            if isinstance(data, dict) and "error" not in data:
                data["error"] = f"HTTP {resp.status_code}"
            if isinstance(data, dict):
                data.setdefault("status", resp.status_code)

        return data

    async def get(self, path: str, params: dict | None = None) -> dict:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, payload: dict | None = None) -> dict:
        return await self._request("POST", path, json=payload)

    async def put(self, path: str, payload: dict | None = None) -> dict:
        return await self._request("PUT", path, json=payload)

    async def delete(self, path: str) -> dict:
        return await self._request("DELETE", path)

    async def close(self) -> None:
        await self._client.aclose()


def fmt(data: Any, indent: int = 2) -> str:
    """Format any value as a readable string for MCP tool output."""
    if isinstance(data, str):
        return data
    try:
        return json.dumps(data, indent=indent, default=str, ensure_ascii=False)
    except Exception:
        return str(data)
