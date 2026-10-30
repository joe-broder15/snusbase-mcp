"""Typed client for the documented Snusbase HTTP API.

This package is the HTTP layer. An MCP server can be added later beside it
(``src/snusbase_mcp``); it is not part of this package.
"""

from snusbase_client.client import SnusbaseClient, SnusbaseResponse
from snusbase_client.endpoints import DEFAULT_BASE_URL, DEFAULT_TIMEOUT_SECONDS, ENV_API_KEY
from snusbase_client.exceptions import (
    SnusbaseAPIError,
    SnusbaseAuthError,
    SnusbaseBadRequestError,
    SnusbaseError,
    SnusbaseRateLimitError,
)
from snusbase_client.models import (
    ComboLookupResponse,
    CountResponse,
    DomainWhoisRecord,
    DomainWhoisResponse,
    HashLookupResponse,
    IpWhoisRecord,
    IpWhoisResponse,
    SearchResponse,
    StatsResponse,
)
from snusbase_client.ratelimit import RateLimit, parse_rate_limit
from snusbase_client.types import (
    ComboLookupType,
    ComboLookupTypeName,
    HashLookupType,
    HashLookupTypeName,
    SearchType,
    SearchTypeName,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "ENV_API_KEY",
    "ComboLookupResponse",
    "ComboLookupType",
    "ComboLookupTypeName",
    "CountResponse",
    "DomainWhoisRecord",
    "DomainWhoisResponse",
    "HashLookupResponse",
    "HashLookupType",
    "HashLookupTypeName",
    "IpWhoisRecord",
    "IpWhoisResponse",
    "RateLimit",
    "SearchResponse",
    "SearchType",
    "SearchTypeName",
    "SnusbaseAPIError",
    "SnusbaseAuthError",
    "SnusbaseBadRequestError",
    "SnusbaseClient",
    "SnusbaseError",
    "SnusbaseRateLimitError",
    "SnusbaseResponse",
    "StatsResponse",
    "__version__",
    "parse_rate_limit",
]
