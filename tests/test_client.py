"""HTTP behavior, mocked. No test in this file opens a socket."""

import asyncio
import json
import logging
from typing import Any

import httpx
import pytest

from snusbase_client import (
    AsyncSnusbaseClient,
    ComboLookupType,
    CountResponse,
    HashLookupType,
    SearchType,
    SnusbaseAPIError,
    SnusbaseAuthError,
    SnusbaseBadRequestError,
    SnusbaseClient,
    SnusbaseRateLimitError,
    SnusbaseResponse,
)
from snusbase_client.endpoints import DEFAULT_BASE_URL, ENV_API_KEY, OPERATIONS
from snusbase_client.models import (
    ComboLookupResponse,
    DomainWhoisResponse,
    HashLookupResponse,
    IpWhoisResponse,
    SearchResponse,
    StatsResponse,
)
from snusbase_client.ratelimit import parse_rate_limit

API_KEY = "sb" + "0" * 28
LEAK_KEY = "sbLEAK0123456789abcdef01234567"

RATE_HEADERS = {
    "X-Rate-Limit": "2048",
    "X-Rate-Limit-Remaining": "2047",
    "X-Rate-Limit-Reset": "100",
}

SUCCESS_BODIES: dict[str, dict[str, Any]] = {
    "stats": {
        "rows": 3,
        "tables": {"T": ["email", "username"]},
        "features": {"view_more": ["T"], "combo_lookup": []},
    },
    "search": {
        "took": 1.5,
        "size": 1,
        "results": {"T": [{"email": "example@gmail.com"}]},
    },
    "count": {"took": 1, "size": 4, "results": {"T": 4}},
    "combo_lookup": {
        "took": 1,
        "size": 1,
        "results": {"C": [{"username": "example@gmail.com", "password": "secret"}]},
    },
    "hash_lookup": {
        "took": 0.1,
        "size": 1,
        "results": {"HASHES": [{"hash": "abc", "password": "secret"}]},
    },
    "ip_whois": {
        "took": 1,
        "size": 1,
        "results": {"1.2.3.4": {"query": "1.2.3.4", "country": "US"}},
    },
    "domain_whois": {
        "took": 1,
        "size": 1,
        "results": {"example.org": {"domain": "example.org", "tld": "org"}},
        "errors": ["missing.test: Likely not registered"],
    },
}

EXPECTED_MODEL = {
    "stats": StatsResponse,
    "search": SearchResponse,
    "count": CountResponse,
    "combo_lookup": ComboLookupResponse,
    "hash_lookup": HashLookupResponse,
    "ip_whois": IpWhoisResponse,
    "domain_whois": DomainWhoisResponse,
}


def _call(client: SnusbaseClient | AsyncSnusbaseClient, name: str) -> Any:
    if name == "stats":
        return client.stats()
    if name == "search":
        return client.search(["example@gmail.com"], [SearchType.EMAIL])
    if name == "count":
        return client.count(["example@gmail.com"], [SearchType.EMAIL])
    if name == "combo_lookup":
        return client.combo_lookup(["example@gmail.com"], [ComboLookupType.USERNAME])
    if name == "hash_lookup":
        return client.hash_lookup(["abc"], [HashLookupType.HASH])
    if name == "ip_whois":
        return client.ip_whois(["1.2.3.4"])
    if name == "domain_whois":
        return client.domain_whois(["example.org"])
    raise AssertionError(name)


def execute(mode: str, api_key: str | None, name: str) -> SnusbaseResponse[Any]:
    if mode == "sync":
        with SnusbaseClient(api_key=api_key) as client:
            return _call(client, name)

    async def _go() -> SnusbaseResponse[Any]:
        async with AsyncSnusbaseClient(api_key=api_key) as client:
            return await _call(client, name)

    return asyncio.run(_go())


def _url(name: str) -> tuple[str, str]:
    method, path = OPERATIONS[name]
    return method, DEFAULT_BASE_URL + path


def _mock(
    router: Any,
    name: str,
    *,
    status: int,
    payload: dict[str, Any] | None,
    headers: dict[str, str] | None = None,
) -> Any:
    method, url = _url(name)
    kwargs: dict[str, Any] = {"status_code": status, "headers": headers or {}}
    if payload is not None:
        kwargs["json"] = payload
    return getattr(router, method.lower())(url).mock(return_value=httpx.Response(**kwargs))


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("name", list(OPERATIONS))
def test_success_and_auth_header(router: Any, mode: str, name: str) -> None:
    headers = None if name == "stats" else RATE_HEADERS
    _mock(router, name, status=200, payload=SUCCESS_BODIES[name], headers=headers)
    result = execute(mode, API_KEY, name)
    assert isinstance(result.data, EXPECTED_MODEL[name])
    assert result.status_code == 200
    request = router.calls[0].request
    if name == "stats":
        assert "auth" not in request.headers
        assert result.rate_limit.limit is None
        assert result.rate_limit.remaining is None
        assert result.rate_limit.reset_seconds is None
    else:
        assert request.headers["Auth"] == API_KEY
        assert request.headers["content-type"].startswith("application/json")
        assert result.rate_limit.limit == 2048
        assert result.rate_limit.remaining == 2047
        assert result.rate_limit.reset_seconds == 100
    if name == "domain_whois":
        assert result.data.errors == ["missing.test: Likely not registered"]


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("name", list(OPERATIONS))
@pytest.mark.parametrize(
    ("status", "exc_type"),
    [
        (400, SnusbaseBadRequestError),
        (401, SnusbaseAuthError),
        (429, SnusbaseRateLimitError),
    ],
)
def test_documented_error_statuses(
    router: Any,
    mode: str,
    name: str,
    status: int,
    exc_type: type[Exception],
) -> None:
    headers = {
        "X-Rate-Limit": "256",
        "X-Rate-Limit-Remaining": "0",
        "X-Rate-Limit-Reset": "3600",
    }
    _mock(
        router,
        name,
        status=status,
        payload={"errors": [f"status {status}"]},
        headers=headers,
    )
    with pytest.raises(exc_type) as caught:
        execute(mode, API_KEY, name)
    err = caught.value
    assert err.status_code == status
    assert err.errors == [f"status {status}"]
    assert API_KEY not in str(err)
    assert API_KEY not in repr(err)
    assert err.rate_limit.remaining == 0
    if isinstance(err, SnusbaseRateLimitError):
        assert err.reset_seconds == 3600
        assert err.rate_limit.reset_seconds == 3600


def test_stats_without_a_key(router: Any) -> None:
    _mock(router, "stats", status=200, payload=SUCCESS_BODIES["stats"])
    with SnusbaseClient() as client:
        result = client.stats()
    assert result.data.rows == 3
    assert "auth" not in router.calls[0].request.headers
    assert len(router.calls) == 1


def test_missing_key_does_not_send(router: Any) -> None:
    with SnusbaseClient() as client:
        with pytest.raises(SnusbaseAuthError, match="SNUSBASE_API_KEY"):
            client.search(["ada@example.com"], [SearchType.EMAIL])
    assert len(router.calls) == 0


def test_empty_key_is_rejected_before_any_request() -> None:
    with pytest.raises(SnusbaseAuthError, match="empty"):
        SnusbaseClient(api_key="")
    with pytest.raises(SnusbaseAuthError, match="empty"):
        SnusbaseClient(api_key="   ")


def test_env_key_and_constructor_override(router: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _mock(router, "search", status=200, payload=SUCCESS_BODIES["search"], headers=RATE_HEADERS)
    monkeypatch.setenv(ENV_API_KEY, LEAK_KEY)
    with SnusbaseClient() as client:
        client.search(["example@gmail.com"], [SearchType.EMAIL])
        assert LEAK_KEY not in repr(client)
        assert LEAK_KEY not in str(client)
    assert router.calls[0].request.headers["Auth"] == LEAK_KEY

    other = "sb" + "a" * 28
    _mock(router, "count", status=200, payload=SUCCESS_BODIES["count"], headers=RATE_HEADERS)
    with SnusbaseClient(api_key=other) as client:
        client.count(["example@gmail.com"], ["email"])
    assert router.calls[1].request.headers["Auth"] == other


def test_blank_env_still_allows_stats(router: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, "   ")
    _mock(router, "stats", status=200, payload=SUCCESS_BODIES["stats"])
    with SnusbaseClient() as client:
        assert client.stats().data.rows == 3


def test_key_is_not_logged(router: Any, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger("httpx").setLevel(logging.DEBUG)
    _mock(
        router,
        "search",
        status=401,
        payload={"errors": ["invalid api key"]},
        headers=RATE_HEADERS,
    )
    with SnusbaseClient(api_key=LEAK_KEY) as client:
        assert LEAK_KEY not in repr(client._api_key)
        with pytest.raises(SnusbaseAuthError) as caught:
            client.search(["example@gmail.com"], [SearchType.EMAIL])
    assert LEAK_KEY not in str(caught.value)
    assert LEAK_KEY not in caplog.text
    assert len(LEAK_KEY) == 30


def test_search_body_and_string_types(router: Any) -> None:
    _mock(router, "search", status=200, payload=SUCCESS_BODIES["search"], headers=RATE_HEADERS)
    with SnusbaseClient(api_key=API_KEY) as client:
        client.search(
            ["example", "other"],
            ["username", "_domain"],
            wildcard=False,
            group_by=False,
            tables=["0001_STEALERLOGS_NA_106M_MALWARE_2023"],
        )
    body = json.loads(router.calls[0].request.content)
    assert body == {
        "terms": ["example", "other"],
        "types": ["username", "_domain"],
        "wildcard": False,
        "group_by": False,
        "tables": ["0001_STEALERLOGS_NA_106M_MALWARE_2023"],
    }


def test_minimal_search_omits_optional_fields(router: Any) -> None:
    _mock(router, "search", status=200, payload=SUCCESS_BODIES["search"], headers=RATE_HEADERS)
    with SnusbaseClient(api_key=API_KEY) as client:
        client.search(["example@gmail.com"], [SearchType.EMAIL])
    body = json.loads(router.calls[0].request.content)
    assert body == {"terms": ["example@gmail.com"], "types": ["email"]}


def test_count_include_results_false_round_trip(router: Any) -> None:
    _mock(
        router,
        "count",
        status=200,
        payload={"took": 18.591, "size": 1245},
        headers=RATE_HEADERS,
    )
    with SnusbaseClient(api_key=API_KEY) as client:
        result = client.count(
            ["example@gmail.com"],
            [SearchType.EMAIL],
            include_results=False,
        )
    body = json.loads(router.calls[0].request.content)
    assert body["include_results"] is False
    assert "group_by" not in body
    assert result.data.results is None
    assert result.data.size == 1245


def test_ungrouped_search_list(router: Any) -> None:
    _mock(
        router,
        "search",
        status=200,
        payload={"took": 1, "size": 1, "results": [{"email": "ada@example.com"}]},
        headers=RATE_HEADERS,
    )
    with SnusbaseClient(api_key=API_KEY) as client:
        result = client.search(["ada@example.com"], [SearchType.EMAIL], group_by=False)
    assert result.data.results == [{"email": "ada@example.com"}]


def test_phone_type_is_rejected_locally(router: Any) -> None:
    with SnusbaseClient(api_key=API_KEY) as client:
        with pytest.raises(SnusbaseBadRequestError) as caught:
            client.search(["ada"], ["phone"])
    assert caught.value.status_code is None
    assert len(router.calls) == 0


def test_domain_whois_term_limit(router: Any) -> None:
    _mock(
        router,
        "domain_whois",
        status=200,
        payload={"took": 1, "size": 0, "results": {}},
        headers={
            "X-Rate-Limit": "256",
            "X-Rate-Limit-Remaining": "255",
            "X-Rate-Limit-Reset": "120",
        },
    )
    domains = [f"d{i}.example" for i in range(100)]
    with SnusbaseClient(api_key=API_KEY) as client:
        client.domain_whois(domains, group_by=False)
        with pytest.raises(SnusbaseBadRequestError):
            client.domain_whois(domains + ["one-more.example"])
    body = json.loads(router.calls[0].request.content)
    assert body["terms"] == domains
    assert body["group_by"] is False
    assert len(router.calls) == 1


def test_ip_whois_group_by_field(router: Any) -> None:
    _mock(
        router,
        "ip_whois",
        status=200,
        payload={
            "took": 1,
            "size": 1,
            "results": {"US": [{"country": "United States", "as": "AS1"}]},
        },
        headers=RATE_HEADERS,
    )
    with SnusbaseClient(api_key=API_KEY) as client:
        result = client.ip_whois(["12.34.56.78"], group_by="country")
    body = json.loads(router.calls[0].request.content)
    assert body == {"terms": ["12.34.56.78"], "group_by": "country"}
    assert "types" not in body
    assert result.data.results["US"][0].as_ == "AS1"


def test_combo_and_hash_types(router: Any) -> None:
    _mock(
        router,
        "combo_lookup",
        status=200,
        payload=SUCCESS_BODIES["combo_lookup"],
        headers=RATE_HEADERS,
    )
    _mock(
        router,
        "hash_lookup",
        status=200,
        payload=SUCCESS_BODIES["hash_lookup"],
        headers=RATE_HEADERS,
    )
    with SnusbaseClient(api_key=API_KEY) as client:
        client.combo_lookup(["secret"], ["password"], wildcard=True, group_by="db")
        client.hash_lookup(["secret"], ["password"])
    combo = json.loads(router.calls[0].request.content)
    digest = json.loads(router.calls[1].request.content)
    assert combo == {
        "terms": ["secret"],
        "types": ["password"],
        "wildcard": True,
        "group_by": "db",
    }
    assert digest == {"terms": ["secret"], "types": ["password"]}


def test_non_json_error_malformed_reset_and_other_status(router: Any) -> None:
    _method, url = _url("search")
    router.post(url).mock(
        side_effect=[
            httpx.Response(400, text="nope", headers={"X-Rate-Limit-Reset": "soon"}),
            httpx.Response(500, json={"errors": ["down"]}),
            httpx.Response(302, headers={"Location": "https://evil.example/collect"}),
        ]
    )
    with SnusbaseClient(api_key=API_KEY) as client:
        with pytest.raises(SnusbaseBadRequestError) as caught:
            client.search(["a@example.com"], [SearchType.EMAIL])
        with pytest.raises(SnusbaseAPIError) as caught_api:
            client.search(["a@example.com"], [SearchType.EMAIL])
        with pytest.raises(SnusbaseAPIError, match="redirect") as caught_redirect:
            client.search(["a@example.com"], [SearchType.EMAIL])
    assert caught.value.errors == []
    assert caught.value.rate_limit.reset_seconds is None
    assert "HTTP 400" in str(caught.value)
    assert caught_api.value.status_code == 500
    assert caught_api.value.errors == ["down"]
    assert caught_redirect.value.status_code == 302
    assert "evil.example" not in str(caught_redirect.value)
    assert API_KEY not in str(caught_redirect.value)


def test_schema_mismatch_and_connection_error(router: Any) -> None:
    _mock(router, "search", status=200, payload={"size": 1}, headers=RATE_HEADERS)
    with SnusbaseClient(api_key=API_KEY) as client:
        with pytest.raises(SnusbaseAPIError, match="documented schema"):
            client.search(["a@example.com"], [SearchType.EMAIL])

    router.post(_url("count")[1]).mock(side_effect=httpx.ConnectError("connection refused"))
    with SnusbaseClient(api_key=LEAK_KEY) as client:
        with pytest.raises(SnusbaseAPIError, match="ConnectError") as caught:
            client.count(["a@example.com"], [SearchType.EMAIL])
    assert LEAK_KEY not in str(caught.value)
    assert "connection refused" not in str(caught.value)


def test_base_url_timeout_and_close(router: Any) -> None:
    base = "http://snusbase.test"
    router.get(f"{base}/data/stats").mock(
        return_value=httpx.Response(200, json=SUCCESS_BODIES["stats"])
    )
    with SnusbaseClient(base_url=base + "/", timeout=12.5) as client:
        assert client.base_url == base
        assert client.timeout == 12.5
        assert client._http.timeout == httpx.Timeout(12.5)
        client.stats()
    assert client._http.is_closed
    with pytest.raises(SnusbaseAPIError, match="closed"):
        client.stats()
    client.close()
    with pytest.raises(ValueError):
        SnusbaseClient(base_url="  ")

    async def _closed() -> None:
        async_client = AsyncSnusbaseClient(api_key=API_KEY, timeout=httpx.Timeout(5.0))
        await async_client.aclose()
        assert async_client._http.is_closed
        with pytest.raises(SnusbaseAPIError, match="closed"):
            await async_client.stats()
        await async_client.aclose()

    asyncio.run(_closed())


def test_parse_rate_limit_is_case_insensitive() -> None:
    parsed = parse_rate_limit(
        {
            "x-rate-limit": "256",
            "X-Rate-Limit-Remaining": " 9 ",
            "X-RATE-LIMIT-RESET": "",
        }
    )
    assert parsed.limit == 256
    assert parsed.remaining == 9
    assert parsed.reset_seconds is None
    assert parse_rate_limit({}).limit is None
