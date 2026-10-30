"""MCP tool behavior, mocked. No test in this file opens a socket."""

import asyncio
import json
import logging
from typing import Any

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from snusbase_client.client import DEFAULT_BASE_URL, ENV_API_KEY
from snusbase_client.exceptions import SnusbaseBadRequestError
from snusbase_mcp.routing import split_whois_terms
from snusbase_mcp.server import build_server

API_KEY = "sb" + "0" * 28
LEAK_KEY = "sbLEAK0123456789abcdef01234567"

RATE_HEADERS = {
    "X-Rate-Limit": "256",
    "X-Rate-Limit-Remaining": "255",
    "X-Rate-Limit-Reset": "120",
}


def run[T](body: Any) -> T:
    async def _go() -> T:
        server = build_server()
        lifespan = server.settings.lifespan
        assert lifespan is not None
        async with lifespan(server):
            return await body(server)

    return asyncio.run(_go())


def _mock(
    router: Any,
    path: str,
    *,
    status: int,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> None:
    router.post(DEFAULT_BASE_URL + path).mock(
        return_value=httpx.Response(status, json=payload, headers=headers or {})
    )


def _json(result: Any) -> Any:
    assert result.is_error is False
    block = result.content[0]
    assert block.type == "text"
    return json.loads(block.text)


def test_split_whois_terms_classifies_ip_and_domain() -> None:
    ips, domains = split_whois_terms([" 1.2.3.4 ", "Example.ORG", "2001:db8::1"])
    assert ips == ["1.2.3.4", "2001:db8::1"]
    assert domains == ["Example.ORG"]


def test_split_whois_terms_rejects_blank() -> None:
    with pytest.raises(SnusbaseBadRequestError):
        split_whois_terms([])
    with pytest.raises(SnusbaseBadRequestError):
        split_whois_terms(["example.org", "  "])


def test_split_whois_terms_rejects_over_100_domains() -> None:
    domains = [f"d{i}.example" for i in range(101)]
    with pytest.raises(SnusbaseBadRequestError):
        split_whois_terms(domains)
    with pytest.raises(SnusbaseBadRequestError):
        split_whois_terms([*domains, "1.2.3.4"])


def test_server_exposes_only_whois_and_search() -> None:
    async def body(server: Any) -> None:
        tools = {tool.name: tool for tool in await server.list_tools()}
        assert set(tools) == {"whois", "search"}
        search = tools["search"]
        description = search.description.lower()
        assert "untrusted" in description
        assert "password" in description
        assert set(search.input_schema["properties"]) == {"terms", "types"}
        schema = json.dumps(search.input_schema)
        for name in ("email", "username", "lastip", "password", "hash", "name", "_domain"):
            assert name in schema
        assert set(tools["whois"].input_schema["properties"]) == {"terms"}

    run(body)


def test_mixed_whois_routes_and_omits_group_by(
    router: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _mock(
        router,
        "/tools/ip-whois",
        status=200,
        payload={
            "took": 1,
            "size": 1,
            "results": {"1.2.3.4": {"query": "1.2.3.4", "country": "US"}},
        },
        headers=RATE_HEADERS,
    )
    _mock(
        router,
        "/tools/domain-whois",
        status=200,
        payload={
            "took": 2,
            "size": 1,
            "results": {"example.org": {"domain": "example.org"}},
            "errors": ["missing.test: Likely not registered"],
        },
        headers={
            "X-Rate-Limit": "256",
            "X-Rate-Limit-Remaining": "254",
            "X-Rate-Limit-Reset": "90",
        },
    )

    async def body(server: Any) -> Any:
        return await server.call_tool("whois", {"terms": [" 1.2.3.4 ", "example.org"]})

    payload = _json(run(body))
    assert [call.request.url.path for call in router.calls] == [
        "/tools/ip-whois",
        "/tools/domain-whois",
    ]
    assert json.loads(router.calls[0].request.content) == {"terms": ["1.2.3.4"]}
    assert json.loads(router.calls[1].request.content) == {"terms": ["example.org"]}
    assert payload["ip"]["results"]["1.2.3.4"]["country"] == "US"
    assert payload["ip"]["rate_limit"]["remaining"] == 255
    assert "errors" not in payload["ip"]
    assert payload["domain"]["errors"] == ["missing.test: Likely not registered"]
    assert payload["domain"]["rate_limit"]["reset_seconds"] == 90
    assert set(payload) == {"ip", "domain"}


def test_domain_only_whois_makes_one_call(router: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _mock(
        router,
        "/tools/domain-whois",
        status=200,
        payload={"took": 1, "size": 1, "results": {"example.org": {"tld": "org"}}},
        headers=RATE_HEADERS,
    )

    async def body(server: Any) -> Any:
        return await server.call_tool("whois", {"terms": ["example.org"]})

    payload = _json(run(body))
    assert len(router.calls) == 1
    assert router.calls[0].request.url.path == "/tools/domain-whois"
    assert set(payload) == {"domain"}
    assert "errors" not in payload["domain"]


def test_whois_over_limit_does_not_send(router: Any) -> None:
    terms = [f"d{i}.example" for i in range(101)]

    async def body(server: Any) -> None:
        with pytest.raises(ToolError):
            await server.call_tool("whois", {"terms": [*terms, "8.8.8.8"]})

    run(body)
    assert len(router.calls) == 0


def test_search_posts_terms_and_types_only(
    router: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    password = "hunter2-leak"
    _mock(
        router,
        "/data/search",
        status=200,
        payload={
            "took": 1.5,
            "size": 1,
            "results": {"T": [{"email": "ada@example.com", "password": password}]},
        },
        headers={
            "X-Rate-Limit": "2048",
            "X-Rate-Limit-Remaining": "2047",
            "X-Rate-Limit-Reset": "100",
        },
    )

    async def body(server: Any) -> Any:
        return await server.call_tool(
            "search",
            {"terms": ["ada@example.com"], "types": ["email", "username"]},
        )

    payload = _json(run(body))
    assert len(router.calls) == 1
    assert router.calls[0].request.url.path == "/data/search"
    assert json.loads(router.calls[0].request.content) == {
        "terms": ["ada@example.com"],
        "types": ["email", "username"],
    }
    assert payload["results"]["T"][0]["password"] == password
    assert payload["rate_limit"]["remaining"] == 2047
    assert password not in caplog.text


def test_rate_limit_surfaces_reset_seconds(router: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, API_KEY)
    _mock(
        router,
        "/data/search",
        status=429,
        payload={"errors": ["slow down"]},
        headers={
            "X-Rate-Limit": "2048",
            "X-Rate-Limit-Remaining": "0",
            "X-Rate-Limit-Reset": "3600",
        },
    )

    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match=r"reset_seconds=3600") as caught:
            await server.call_tool("search", {"terms": ["ada@example.com"], "types": ["email"]})
        assert "slow down" in str(caught.value)
        assert API_KEY not in str(caught.value)

    run(body)


def test_missing_key_does_not_send(router: Any, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)

    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match="SNUSBASE_API_KEY") as caught:
            await server.call_tool("search", {"terms": ["ada@example.com"], "types": ["email"]})
        assert LEAK_KEY not in str(caught.value)

    run(body)
    assert len(router.calls) == 0


def test_auth_failure_names_env_and_hides_key(
    router: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv(ENV_API_KEY, LEAK_KEY)
    _mock(
        router,
        "/data/search",
        status=401,
        payload={"errors": ["invalid api key"]},
        headers=RATE_HEADERS,
    )

    async def body(server: Any) -> None:
        with pytest.raises(ToolError, match="SNUSBASE_API_KEY") as caught:
            await server.call_tool("search", {"terms": ["ada@example.com"], "types": ["email"]})
        assert LEAK_KEY not in str(caught.value)

    run(body)
    assert LEAK_KEY not in caplog.text
