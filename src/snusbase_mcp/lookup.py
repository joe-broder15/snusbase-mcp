"""Call the client for the two MCP tools and shape the result the agent sees."""

from typing import Any

from snusbase_client import (
    SearchType,
    SnusbaseAuthError,
    SnusbaseClient,
    SnusbaseError,
    SnusbaseRateLimitError,
    SnusbaseResponse,
)
from snusbase_client.client import ENV_API_KEY
from snusbase_mcp.routing import split_whois_terms


def tool_error_text(exc: SnusbaseError) -> str:
    """Text for a tool error. Names the env var on auth failure, never the key.

    A rate-limit error includes ``reset_seconds`` when the header was an integer.
    """
    if isinstance(exc, SnusbaseAuthError):
        if ENV_API_KEY not in exc.message:
            return f"{exc.message} Set {ENV_API_KEY}."
        return exc.message
    if isinstance(exc, SnusbaseRateLimitError) and exc.reset_seconds is not None:
        return f"{exc.message} reset_seconds={exc.reset_seconds}"
    return exc.message


def _view(response: SnusbaseResponse[Any]) -> dict[str, Any]:
    return {
        "took": response.data.took,
        "size": response.data.size,
        "results": response.data.results,
        "rate_limit": response.rate_limit.model_dump(),
    }


async def lookup_whois(client: SnusbaseClient, terms: list[str]) -> dict[str, Any]:
    """WHOIS for a mixed list. Only the kinds that were sent are present."""
    ips, domains = split_whois_terms(terms)
    out: dict[str, Any] = {}
    if ips:
        out["ip"] = _view(await client.ip_whois(ips))
    if domains:
        found = await client.domain_whois(domains)
        view = _view(found)
        if found.data.errors is not None:
            view["errors"] = found.data.errors
        out["domain"] = view
    return out


async def lookup_search(
    client: SnusbaseClient,
    terms: list[str],
    types: list[SearchType],
) -> dict[str, Any]:
    """``POST /data/search`` with terms and types only."""
    return _view(await client.search(terms, types))
