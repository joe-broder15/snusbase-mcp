"""Sync and async clients for the documented Snusbase API.

The activation code is taken from the ``api_key`` argument or, if that argument
is omitted, from the ``SNUSBASE_API_KEY`` environment variable. It is sent in
the ``Auth`` header. It is never written to a log line by this package, and
``repr`` / ``str`` of the client redact it.

``GET /data/stats`` does not send ``Auth``, including when a key is configured.
The stats section of the docs shows a request with no auth header. The generic
code samples send ``Auth`` on every call only because their helper always sets
the header.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from os import environ
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError

from snusbase_client.exceptions import (
    SnusbaseAPIError,
    SnusbaseAuthError,
    SnusbaseBadRequestError,
    SnusbaseError,
    SnusbaseRateLimitError,
)
from snusbase_client.models import (
    ComboLookupRequest,
    ComboLookupResponse,
    ComboLookupType,
    ComboLookupTypeName,
    CountRequest,
    CountResponse,
    DomainWhoisRequest,
    DomainWhoisResponse,
    HashLookupRequest,
    HashLookupResponse,
    HashLookupType,
    HashLookupTypeName,
    IpWhoisRequest,
    IpWhoisResponse,
    RateLimit,
    SearchRequest,
    SearchResponse,
    SearchType,
    SearchTypeName,
    StatsResponse,
)

DEFAULT_BASE_URL = "https://api.snusbase.com"
DEFAULT_TIMEOUT_SECONDS = 60.0
ENV_API_KEY = "SNUSBASE_API_KEY"
AUTH_HEADER = "Auth"

PATH_STATS = "/data/stats"
PATH_SEARCH = "/data/search"
PATH_COUNT = "/data/count"
PATH_COMBO_LOOKUP = "/tools/combo-lookup"
PATH_HASH_LOOKUP = "/tools/hash-lookup"
PATH_IP_WHOIS = "/tools/ip-whois"
PATH_DOMAIN_WHOIS = "/tools/domain-whois"

# Public client method name -> (HTTP method, path).
OPERATIONS: dict[str, tuple[str, str]] = {
    "stats": ("GET", PATH_STATS),
    "search": ("POST", PATH_SEARCH),
    "count": ("POST", PATH_COUNT),
    "combo_lookup": ("POST", PATH_COMBO_LOOKUP),
    "hash_lookup": ("POST", PATH_HASH_LOOKUP),
    "ip_whois": ("POST", PATH_IP_WHOIS),
    "domain_whois": ("POST", PATH_DOMAIN_WHOIS),
}


class _Secret:
    """Holds the activation code. ``str`` and ``repr`` never reveal it."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def __repr__(self) -> str:
        return "_Secret(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def __format__(self, format_spec: str) -> str:
        return "<redacted>"

    def reveal(self) -> str:
        return self._value


@dataclass(frozen=True, slots=True)
class SnusbaseResponse[T: BaseModel]:
    """Parsed body plus the rate-limit headers from that response."""

    data: T
    rate_limit: RateLimit
    status_code: int


def _resolve_api_key(api_key: str | None) -> str | None:
    if api_key is not None:
        if not api_key.strip():
            raise SnusbaseAuthError("API key is empty.")
        return api_key
    env = environ.get(ENV_API_KEY)
    if env is None or not env.strip():
        return None
    return env


def _validation_messages(exc: ValidationError) -> list[str]:
    messages: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ()))
        msg = str(err.get("msg", "invalid value"))
        messages.append(f"{loc}: {msg}" if loc else msg)
    return messages


def _payload(model: type[BaseModel], /, **data: Any) -> dict[str, Any]:
    try:
        parsed = model.model_validate(data)
    except ValidationError as exc:
        raise SnusbaseBadRequestError(
            "Request does not match the documented parameters.",
            errors=_validation_messages(exc),
        ) from None
    return parsed.model_dump(mode="json", exclude_none=True)


def _errors_from_body(response: httpx.Response) -> list[str]:
    try:
        payload = response.json()
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    raw = payload.get("errors")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        messages: list[str] = []
        for item in raw:
            if isinstance(item, str):
                messages.append(item)
            else:
                messages.append(str(item))
        return messages
    return [str(raw)]


def _error_from_response(response: httpx.Response, rate_limit: RateLimit) -> SnusbaseError:
    errors = _errors_from_body(response)
    message = "; ".join(errors) if errors else f"HTTP {response.status_code}"
    if response.status_code == 400:
        return SnusbaseBadRequestError(
            message,
            status_code=response.status_code,
            errors=errors,
            rate_limit=rate_limit,
        )
    if response.status_code == 401:
        return SnusbaseAuthError(
            message,
            status_code=response.status_code,
            errors=errors,
            rate_limit=rate_limit,
        )
    if response.status_code == 429:
        return SnusbaseRateLimitError(
            message,
            reset_seconds=rate_limit.reset_seconds,
            status_code=response.status_code,
            errors=errors,
            rate_limit=rate_limit,
        )
    return SnusbaseAPIError(
        message,
        status_code=response.status_code,
        errors=errors,
        rate_limit=rate_limit,
    )


def _parse_response[T: BaseModel](response: httpx.Response, model: type[T]) -> SnusbaseResponse[T]:
    rate_limit = parse_rate_limit(response.headers)
    if not response.is_success:
        if 300 <= response.status_code < 400:
            raise SnusbaseAPIError(
                f"Unexpected redirect (HTTP {response.status_code}). Redirects are not followed.",
                status_code=response.status_code,
                rate_limit=rate_limit,
            )
        raise _error_from_response(response, rate_limit)
    try:
        payload = response.json()
    except ValueError:
        raise SnusbaseAPIError(
            f"Expected a JSON object (HTTP {response.status_code}).",
            status_code=response.status_code,
            rate_limit=rate_limit,
        ) from None
    try:
        data = model.model_validate(payload)
    except ValidationError as exc:
        raise SnusbaseAPIError(
            f"Response did not match the documented schema (HTTP {response.status_code}).",
            status_code=response.status_code,
            errors=_validation_messages(exc),
            rate_limit=rate_limit,
        ) from None
    return SnusbaseResponse(data=data, rate_limit=rate_limit, status_code=response.status_code)


def _request_kwargs(
    api_key: _Secret | None,
    *,
    json_body: dict[str, Any] | None,
    authenticated: bool,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if json_body is not None:
        kwargs["json"] = json_body
    if not authenticated:
        return kwargs
    if api_key is None:
        raise SnusbaseAuthError(
            "An API key is required for this endpoint. "
            "Pass api_key or set the SNUSBASE_API_KEY environment variable."
        )
    headers = {
        AUTH_HEADER: api_key.reveal(),
        "Content-Type": "application/json",
    }
    kwargs["headers"] = headers
    return kwargs


def _check_base_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must be a non-empty string")
    return base_url.rstrip("/")


def _client_repr(
    kind: str, base_url: str, timeout: float | httpx.Timeout, api_key: _Secret | None
) -> str:
    return f"{kind}(base_url={base_url!r}, timeout={timeout!r}, api_key_set={api_key is not None})"


def parse_rate_limit(headers: Mapping[str, str]) -> RateLimit:
    """Read rate-limit headers. Lookup is case-insensitive."""

    def optional_int(name: str) -> int | None:
        target = name.lower()
        for key, value in headers.items():
            if key.lower() != target:
                continue
            raw = value.strip()
            if raw == "":
                return None
            try:
                return int(raw)
            except ValueError:
                return None
        return None

    return RateLimit(
        limit=optional_int("X-Rate-Limit"),
        remaining=optional_int("X-Rate-Limit-Remaining"),
        reset_seconds=optional_int("X-Rate-Limit-Reset"),
    )


class SnusbaseClient:
    """Synchronous client. Use as a context manager so the connection pool closes.

    ``timeout`` is forwarded to httpx (a float sets every phase, in seconds).
    The unit of the response ``took`` field is not documented; domain WHOIS in
    particular can be slow, so raise ``timeout`` for large batches.
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.base_url = _check_base_url(base_url)
        self.timeout = timeout
        resolved = _resolve_api_key(api_key)
        self._api_key = _Secret(resolved) if resolved is not None else None
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=False,
        )

    def __repr__(self) -> str:
        return _client_repr(type(self).__name__, self.base_url, self.timeout, self._api_key)

    def __str__(self) -> str:
        return repr(self)

    def __enter__(self) -> "SnusbaseClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def stats(self) -> SnusbaseResponse[StatsResponse]:
        """``GET /data/stats``. Does not send the ``Auth`` header."""
        return self._call("stats", StatsResponse, None, authenticated=False)

    def search(
        self,
        terms: Sequence[str],
        types: Sequence[SearchType | SearchTypeName],
        *,
        wildcard: bool | None = None,
        group_by: bool | str | None = None,
        tables: Sequence[str] | None = None,
    ) -> SnusbaseResponse[SearchResponse]:
        """``POST /data/search``.

        Omit ``group_by`` to use the server default ``"db"``. Pass ``False`` to
        disable grouping. ``tables`` limits which databases are searched and asks
        for every column (View More). Rows can include plaintext credentials and
        unsanitized HTML or exploit payloads. Treat every field as untrusted.
        """
        return self._call(
            "search",
            SearchResponse,
            _payload(
                SearchRequest,
                terms=list(terms),
                types=list(types),
                wildcard=wildcard,
                group_by=group_by,
                tables=None if tables is None else list(tables),
            ),
            authenticated=True,
        )

    def count(
        self,
        terms: Sequence[str],
        types: Sequence[SearchType | SearchTypeName],
        *,
        wildcard: bool | None = None,
        tables: Sequence[str] | None = None,
        include_results: bool | None = None,
    ) -> SnusbaseResponse[CountResponse]:
        """``POST /data/count``.

        Omit ``include_results`` to use the server default ``true``. Pass
        ``False`` to get only ``took`` and ``size``. There is no ``group_by``.
        """
        return self._call(
            "count",
            CountResponse,
            _payload(
                CountRequest,
                terms=list(terms),
                types=list(types),
                wildcard=wildcard,
                tables=None if tables is None else list(tables),
                include_results=include_results,
            ),
            authenticated=True,
        )

    def combo_lookup(
        self,
        terms: Sequence[str],
        types: Sequence[ComboLookupType | ComboLookupTypeName],
        *,
        wildcard: bool | None = None,
        group_by: bool | str | None = None,
    ) -> SnusbaseResponse[ComboLookupResponse]:
        """``POST /tools/combo-lookup``. Types are ``username`` and ``password``.

        Rows can include plaintext credentials and unsanitized HTML or exploit
        payloads. Treat every field as untrusted.
        """
        return self._call(
            "combo_lookup",
            ComboLookupResponse,
            _payload(
                ComboLookupRequest,
                terms=list(terms),
                types=list(types),
                wildcard=wildcard,
                group_by=group_by,
            ),
            authenticated=True,
        )

    def hash_lookup(
        self,
        terms: Sequence[str],
        types: Sequence[HashLookupType | HashLookupTypeName],
        *,
        wildcard: bool | None = None,
        group_by: bool | str | None = None,
    ) -> SnusbaseResponse[HashLookupResponse]:
        """``POST /tools/hash-lookup``. Types are ``hash`` and ``password``.

        Rows can include plaintext passwords and unsanitized HTML or exploit
        payloads. Treat every field as untrusted.
        """
        return self._call(
            "hash_lookup",
            HashLookupResponse,
            _payload(
                HashLookupRequest,
                terms=list(terms),
                types=list(types),
                wildcard=wildcard,
                group_by=group_by,
            ),
            authenticated=True,
        )

    def ip_whois(
        self,
        terms: Sequence[str],
        *,
        group_by: bool | str | None = None,
    ) -> SnusbaseResponse[IpWhoisResponse]:
        """``POST /tools/ip-whois``.

        Omit ``group_by`` for an object keyed by IP. A string groups by that
        field. ``False`` returns a flat list. The default is not ``"db"``.
        """
        return self._call(
            "ip_whois",
            IpWhoisResponse,
            _payload(IpWhoisRequest, terms=list(terms), group_by=group_by),
            authenticated=True,
        )

    def domain_whois(
        self,
        terms: Sequence[str],
        *,
        group_by: bool | str | None = None,
    ) -> SnusbaseResponse[DomainWhoisResponse]:
        """``POST /tools/domain-whois``. At most 100 domains per request.

        A 200 response can still list per-domain failures on ``data.errors``.
        Omit ``group_by`` for an object keyed by the input domain.
        """
        return self._call(
            "domain_whois",
            DomainWhoisResponse,
            _payload(DomainWhoisRequest, terms=list(terms), group_by=group_by),
            authenticated=True,
        )

    def _call[T: BaseModel](
        self,
        operation: str,
        model: type[T],
        json_body: dict[str, Any] | None,
        *,
        authenticated: bool,
    ) -> SnusbaseResponse[T]:
        method, path = OPERATIONS[operation]
        response = self._send(method, path, json_body=json_body, authenticated=authenticated)
        return _parse_response(response, model)

    def _send(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None,
        authenticated: bool,
    ) -> httpx.Response:
        if self._http.is_closed:
            raise SnusbaseAPIError("Client is closed.")
        kwargs = _request_kwargs(
            self._api_key,
            json_body=json_body,
            authenticated=authenticated,
        )
        try:
            return self._http.request(method, path, **kwargs)
        except httpx.RequestError as exc:
            raise SnusbaseAPIError(f"Request to {path} failed ({type(exc).__name__}).") from None


class AsyncSnusbaseClient:
    """Asynchronous client. Use ``async with`` so the connection pool closes."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.base_url = _check_base_url(base_url)
        self.timeout = timeout
        resolved = _resolve_api_key(api_key)
        self._api_key = _Secret(resolved) if resolved is not None else None
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            follow_redirects=False,
        )

    def __repr__(self) -> str:
        return _client_repr(type(self).__name__, self.base_url, self.timeout, self._api_key)

    def __str__(self) -> str:
        return repr(self)

    async def __aenter__(self) -> "AsyncSnusbaseClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def stats(self) -> SnusbaseResponse[StatsResponse]:
        """``GET /data/stats``. Does not send the ``Auth`` header."""
        return await self._call("stats", StatsResponse, None, authenticated=False)

    async def search(
        self,
        terms: Sequence[str],
        types: Sequence[SearchType | SearchTypeName],
        *,
        wildcard: bool | None = None,
        group_by: bool | str | None = None,
        tables: Sequence[str] | None = None,
    ) -> SnusbaseResponse[SearchResponse]:
        """Async ``POST /data/search``. See :meth:`SnusbaseClient.search`."""
        return await self._call(
            "search",
            SearchResponse,
            _payload(
                SearchRequest,
                terms=list(terms),
                types=list(types),
                wildcard=wildcard,
                group_by=group_by,
                tables=None if tables is None else list(tables),
            ),
            authenticated=True,
        )

    async def count(
        self,
        terms: Sequence[str],
        types: Sequence[SearchType | SearchTypeName],
        *,
        wildcard: bool | None = None,
        tables: Sequence[str] | None = None,
        include_results: bool | None = None,
    ) -> SnusbaseResponse[CountResponse]:
        """Async ``POST /data/count``. See :meth:`SnusbaseClient.count`."""
        return await self._call(
            "count",
            CountResponse,
            _payload(
                CountRequest,
                terms=list(terms),
                types=list(types),
                wildcard=wildcard,
                tables=None if tables is None else list(tables),
                include_results=include_results,
            ),
            authenticated=True,
        )

    async def combo_lookup(
        self,
        terms: Sequence[str],
        types: Sequence[ComboLookupType | ComboLookupTypeName],
        *,
        wildcard: bool | None = None,
        group_by: bool | str | None = None,
    ) -> SnusbaseResponse[ComboLookupResponse]:
        """Async ``POST /tools/combo-lookup``. See :meth:`SnusbaseClient.combo_lookup`."""
        return await self._call(
            "combo_lookup",
            ComboLookupResponse,
            _payload(
                ComboLookupRequest,
                terms=list(terms),
                types=list(types),
                wildcard=wildcard,
                group_by=group_by,
            ),
            authenticated=True,
        )

    async def hash_lookup(
        self,
        terms: Sequence[str],
        types: Sequence[HashLookupType | HashLookupTypeName],
        *,
        wildcard: bool | None = None,
        group_by: bool | str | None = None,
    ) -> SnusbaseResponse[HashLookupResponse]:
        """Async ``POST /tools/hash-lookup``. See :meth:`SnusbaseClient.hash_lookup`."""
        return await self._call(
            "hash_lookup",
            HashLookupResponse,
            _payload(
                HashLookupRequest,
                terms=list(terms),
                types=list(types),
                wildcard=wildcard,
                group_by=group_by,
            ),
            authenticated=True,
        )

    async def ip_whois(
        self,
        terms: Sequence[str],
        *,
        group_by: bool | str | None = None,
    ) -> SnusbaseResponse[IpWhoisResponse]:
        """Async ``POST /tools/ip-whois``. See :meth:`SnusbaseClient.ip_whois`."""
        return await self._call(
            "ip_whois",
            IpWhoisResponse,
            _payload(IpWhoisRequest, terms=list(terms), group_by=group_by),
            authenticated=True,
        )

    async def domain_whois(
        self,
        terms: Sequence[str],
        *,
        group_by: bool | str | None = None,
    ) -> SnusbaseResponse[DomainWhoisResponse]:
        """Async ``POST /tools/domain-whois``. See :meth:`SnusbaseClient.domain_whois`."""
        return await self._call(
            "domain_whois",
            DomainWhoisResponse,
            _payload(DomainWhoisRequest, terms=list(terms), group_by=group_by),
            authenticated=True,
        )

    async def _call[T: BaseModel](
        self,
        operation: str,
        model: type[T],
        json_body: dict[str, Any] | None,
        *,
        authenticated: bool,
    ) -> SnusbaseResponse[T]:
        method, path = OPERATIONS[operation]
        response = await self._send(
            method,
            path,
            json_body=json_body,
            authenticated=authenticated,
        )
        return _parse_response(response, model)

    async def _send(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None,
        authenticated: bool,
    ) -> httpx.Response:
        if self._http.is_closed:
            raise SnusbaseAPIError("Client is closed.")
        kwargs = _request_kwargs(
            self._api_key,
            json_body=json_body,
            authenticated=authenticated,
        )
        try:
            return await self._http.request(method, path, **kwargs)
        except httpx.RequestError as exc:
            raise SnusbaseAPIError(f"Request to {path} failed ({type(exc).__name__}).") from None
