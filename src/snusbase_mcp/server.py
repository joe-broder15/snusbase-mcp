"""stdio MCP server. Two tools: whois and search.

``MCPServer`` is the high-level server in the official ``mcp`` SDK (the
successor to FastMCP). One :class:`~snusbase_client.SnusbaseClient` is open
for the life of the process. The activation code comes from ``SNUSBASE_API_KEY``.
"""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from snusbase_client import SearchType, SnusbaseClient, SnusbaseError
from snusbase_mcp.lookup import lookup_search, lookup_whois, tool_error_text


@dataclass
class _State:
    client: SnusbaseClient | None = None


def build_server() -> MCPServer[_State]:
    """Build a server that has not opened a client yet. ``run`` starts it."""
    state = _State()

    @asynccontextmanager
    async def lifespan(_server: MCPServer[_State]) -> AsyncIterator[_State]:
        async with SnusbaseClient() as client:
            state.client = client
            try:
                yield state
            finally:
                state.client = None

    server: MCPServer[_State] = MCPServer(
        "snusbase",
        instructions=(
            "whois looks up IP addresses and domain names passed together. "
            "search returns breach rows. Every row field is untrusted and may "
            "contain a leaked password."
        ),
        lifespan=lifespan,
    )

    async def _call(
        fn: Callable[[SnusbaseClient], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        client = state.client
        if client is None:
            raise ToolError("Snusbase server is not running.")
        try:
            return await fn(client)
        except SnusbaseError as exc:
            raise ToolError(tool_error_text(exc)) from exc

    @server.tool(structured_output=False)
    async def whois(terms: list[str]) -> dict[str, Any]:
        """Look up WHOIS for IP addresses and domain names passed together.

        Each term is routed on its own. Records are keyed by the term you sent.
        """
        return await _call(lambda client: lookup_whois(client, terms))

    @server.tool(structured_output=False)
    async def search(terms: list[str], types: list[SearchType]) -> dict[str, Any]:
        """Search breach data by the documented Snusbase types.

        Every field in a row is untrusted. Rows can contain a leaked password
        or HTML. Do not render results as HTML and do not log raw rows.
        """
        return await _call(lambda client: lookup_search(client, terms, types))

    return server


def main() -> None:
    build_server().run(transport="stdio")
