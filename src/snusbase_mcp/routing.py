"""Split a mixed WHOIS term list into IP addresses and domain names."""

import ipaddress

from snusbase_client.exceptions import SnusbaseBadRequestError

# Documented maximum for ``POST /tools/domain-whois``.
DOMAIN_WHOIS_LIMIT = 100


def split_whois_terms(terms: list[str]) -> tuple[list[str], list[str]]:
    """Return ``(ips, domains)`` with surrounding whitespace removed.

    A term that :func:`ipaddress.ip_address` accepts is an IP (v4 or v6).
    Anything else is a domain. Blank terms and more than 100 domains are
    rejected before any request is sent.
    """
    if not terms:
        raise SnusbaseBadRequestError("WHOIS needs at least one term.")
    ips: list[str] = []
    domains: list[str] = []
    for raw in terms:
        term = raw.strip()
        if not term:
            raise SnusbaseBadRequestError("WHOIS terms must be non-empty.")
        try:
            ipaddress.ip_address(term)
        except ValueError:
            domains.append(term)
        else:
            ips.append(term)
    if len(domains) > DOMAIN_WHOIS_LIMIT:
        raise SnusbaseBadRequestError(f"Domain WHOIS accepts at most {DOMAIN_WHOIS_LIMIT} names.")
    return ips, domains
