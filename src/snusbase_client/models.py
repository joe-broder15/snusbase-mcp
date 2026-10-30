"""Pydantic models for documented Snusbase request and response bodies.

Breach, combo, hash, and WHOIS rows are plain dicts. Columns vary, and the
docs do not say which keys are always present. Request models omit optional
fields that are ``None`` so the server can apply its own defaults (``group_by``
of ``"db"`` on search, combo, and hash; ``include_results`` of true on count).
"""

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class SearchType(StrEnum):
    """``types`` values for ``POST /data/search`` and ``POST /data/count``.

    ``SearchType.DOMAIN`` is the wire value ``_domain``.
    """

    EMAIL = "email"
    USERNAME = "username"
    LASTIP = "lastip"
    PASSWORD = "password"
    HASH = "hash"
    NAME = "name"
    DOMAIN = "_domain"


SearchTypeName = Literal[
    "email",
    "username",
    "lastip",
    "password",
    "hash",
    "name",
    "_domain",
]


class ComboLookupType(StrEnum):
    """``types`` values for ``POST /tools/combo-lookup``."""

    USERNAME = "username"
    PASSWORD = "password"


ComboLookupTypeName = Literal["username", "password"]


class HashLookupType(StrEnum):
    """``types`` values for ``POST /tools/hash-lookup``."""

    HASH = "hash"
    PASSWORD = "password"


HashLookupTypeName = Literal["hash", "password"]


class SearchRequest(BaseModel):
    """Body of ``POST /data/search``."""

    model_config = ConfigDict(extra="forbid")

    terms: list[str]
    types: list[SearchType]
    wildcard: bool | None = None
    group_by: bool | str | None = None
    tables: list[str] | None = None


class CountRequest(BaseModel):
    """Body of ``POST /data/count``. No ``group_by`` parameter is documented."""

    model_config = ConfigDict(extra="forbid")

    terms: list[str]
    types: list[SearchType]
    wildcard: bool | None = None
    tables: list[str] | None = None
    include_results: bool | None = None


class ComboLookupRequest(BaseModel):
    """Body of ``POST /tools/combo-lookup``."""

    model_config = ConfigDict(extra="forbid")

    terms: list[str]
    types: list[ComboLookupType]
    wildcard: bool | None = None
    group_by: bool | str | None = None


class HashLookupRequest(BaseModel):
    """Body of ``POST /tools/hash-lookup``."""

    model_config = ConfigDict(extra="forbid")

    terms: list[str]
    types: list[HashLookupType]
    wildcard: bool | None = None
    group_by: bool | str | None = None


class IpWhoisRequest(BaseModel):
    """Body of ``POST /tools/ip-whois``."""

    model_config = ConfigDict(extra="forbid")

    terms: list[str]
    group_by: bool | str | None = None


class DomainWhoisRequest(BaseModel):
    """Body of ``POST /tools/domain-whois``. ``terms`` has a documented max of 100."""

    model_config = ConfigDict(extra="forbid")

    terms: list[str] = Field(max_length=100)
    group_by: bool | str | None = None


class RateLimit(BaseModel):
    """Rate-limit headers from one response.

    Documented on authenticated requests:

    - ``X-Rate-Limit`` -> ``limit``
    - ``X-Rate-Limit-Remaining`` -> ``remaining``
    - ``X-Rate-Limit-Reset`` -> ``reset_seconds`` (seconds until the window resets)

    Missing or non-integer header values are ``None``. ``GET /data/stats`` is
    unauthenticated, so these are typically absent on that call.
    """

    model_config = ConfigDict(extra="forbid")

    limit: int | None = None
    remaining: int | None = None
    reset_seconds: int | None = None


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="allow")

    took: float
    size: int


# Grouped object (default and column grouping) or a flat list. Search, combo,
# and hash examples only show the object form. ``group_by: false`` is documented
# as disabling grouping but the payload is not shown; a list is accepted so that
# response does not fail parsing.
GroupedRows = dict[str, list[dict[str, Any]]] | list[dict[str, Any]]

# WHOIS omits ``group_by`` to key one record by the input. A string groups into
# arrays plus a ``NO_{FIELD}`` bucket. ``false`` is a flat list.
WhoisRows = dict[str, dict[str, Any] | list[dict[str, Any]]] | list[dict[str, Any]]


class SearchResponse(_Envelope):
    """Body of ``POST /data/search``.

    With the default ``group_by`` of ``"db"``, ``results`` is a dict of table
    name to rows. Rows are not a fixed schema.
    """

    results: GroupedRows


class ComboLookupResponse(_Envelope):
    """Body of ``POST /tools/combo-lookup``. Rows can contain plaintext passwords."""

    results: GroupedRows


class HashLookupResponse(_Envelope):
    """Body of ``POST /tools/hash-lookup``. Rows can contain plaintext passwords."""

    results: GroupedRows


class CountResponse(_Envelope):
    """Body of ``POST /data/count``.

    ``results`` maps table name to a count. It is absent when ``include_results``
    is false.
    """

    results: dict[str, int] | None = None


class StatsFeatures(BaseModel):
    """``features`` object on ``GET /data/stats``."""

    model_config = ConfigDict(extra="allow")

    view_more: list[str]
    combo_lookup: list[str]


class StatsResponse(BaseModel):
    """Body of ``GET /data/stats``."""

    model_config = ConfigDict(extra="allow")

    rows: int
    tables: dict[str, list[str]]
    features: StatsFeatures


class IpWhoisResponse(_Envelope):
    """Body of ``POST /tools/ip-whois``. Records are plain dicts.

    Omitted ``group_by``: object keyed by IP, values are records.
    String ``group_by``: object of arrays, with a ``NO_{FIELD}`` bucket.
    ``group_by=False``: a flat list.
    """

    results: WhoisRows


class DomainWhoisResponse(_Envelope):
    """Body of ``POST /tools/domain-whois``. Records are plain dicts.

    HTTP 200 may still include ``errors`` for inputs that did not resolve.
    That does not raise; read ``errors`` on the model.
    """

    results: WhoisRows
    errors: list[str] | None = None
