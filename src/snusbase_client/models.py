"""Pydantic models for documented Snusbase request and response bodies.

Breach, combo, and hash rows are plain dicts: columns vary by table, and
``GET /data/stats`` is what lists them. WHOIS records follow the published
examples, with extra keys kept (``extra="allow"``) and no field marked required,
because the docs do not say which keys are always present.

Request models omit optional fields that are ``None`` so the server can apply
its own defaults (``group_by`` of ``"db"`` on search, combo, and hash;
``include_results`` of true on count).
"""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from snusbase_client.types import (
    ComboLookupType,
    HashLookupType,
    SearchType,
)


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


class _Envelope(BaseModel):
    model_config = ConfigDict(extra="allow")

    took: float
    size: int


# Grouped object (default and column grouping) or a flat list. Search, combo,
# and hash examples only show the object form. ``group_by: false`` is documented
# as disabling grouping but the payload is not shown; a list is accepted so that
# response does not fail parsing. Whois docs do show the flat array.
GroupedRows = dict[str, list[dict[str, Any]]] | list[dict[str, Any]]


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


class IpWhoisRecord(BaseModel):
    """One IP WHOIS record from the documented example.

    ``as_`` is the JSON field ``as`` (``as`` is not a legal Python name).
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    query: str | None = None
    continent: str | None = None
    continentCode: str | None = None
    country: str | None = None
    countryCode: str | None = None
    region: str | None = None
    regionName: str | None = None
    city: str | None = None
    zip: str | None = None
    lat: float | None = None
    lon: float | None = None
    timezone: str | None = None
    isp: str | None = None
    org: str | None = None
    as_: str | None = Field(default=None, alias="as")
    asname: str | None = None
    mobile: bool | None = None
    proxy: bool | None = None
    hosting: bool | None = None


IpWhoisResults = dict[str, IpWhoisRecord | list[IpWhoisRecord]] | list[IpWhoisRecord]


class IpWhoisResponse(_Envelope):
    """Body of ``POST /tools/ip-whois``.

    Omitted ``group_by``: object keyed by IP, values are records.
    String ``group_by``: object of arrays, with a ``NO_{FIELD}`` bucket.
    ``group_by=False``: a flat list.
    """

    results: IpWhoisResults


class DomainDate(BaseModel):
    model_config = ConfigDict(extra="allow")

    created: str | None = None
    expires: str | None = None
    updated: str | None = None


class DomainRegistrar(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str | None = None
    handle: str | None = None


class DomainMeta(BaseModel):
    """Sample records use ``sources``. ``meta.source`` is only named as a group_by path."""

    model_config = ConfigDict(extra="allow")

    checked: str | None = None
    updated: str | None = None
    seen_czds: str | None = None
    sources: list[str] | None = None


class DomainDnsValue(BaseModel):
    """MX-style ``dns.records[].values`` item (``priority``, ``server``)."""

    model_config = ConfigDict(extra="allow")

    priority: int | None = None
    server: str | None = None


class DomainDnsRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: str | None = None
    name: str | None = None
    ttl: int | None = None
    values: list[str | DomainDnsValue] | None = None


class DomainDnsSecurity(BaseModel):
    model_config = ConfigDict(extra="allow")

    signed: bool | None = None


class DomainDns(BaseModel):
    model_config = ConfigDict(extra="allow")

    security: DomainDnsSecurity | None = None
    records: list[DomainDnsRecord] | None = None


class DomainWhoisRecord(BaseModel):
    """One domain WHOIS/RDAP record.

    ``registrant`` is optional. The group_by docs mention ``registrant.org``;
    the sample record puts party data under ``contact`` instead.
    """

    model_config = ConfigDict(extra="allow")

    domain: str | None = None
    tld: str | None = None
    date: DomainDate | None = None
    nameserver: list[str] | None = None
    registrar: DomainRegistrar | None = None
    status: list[str] | None = None
    contact: dict[str, Any] | None = None
    registrant: dict[str, Any] | None = None
    meta: DomainMeta | None = None
    dns: DomainDns | None = None


DomainWhoisResults = (
    dict[str, DomainWhoisRecord | list[DomainWhoisRecord]] | list[DomainWhoisRecord]
)


class DomainWhoisResponse(_Envelope):
    """Body of ``POST /tools/domain-whois``.

    HTTP 200 may still include ``errors`` for inputs that did not resolve.
    That does not raise; read ``errors`` on the model.
    """

    results: DomainWhoisResults
    errors: list[str] | None = None
