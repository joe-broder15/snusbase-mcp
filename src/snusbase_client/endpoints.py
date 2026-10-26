"""Documented Snusbase paths. The OpenAPI spec is checked against ``OPERATIONS``."""

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
