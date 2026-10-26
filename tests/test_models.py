"""Response shapes described in prose, beyond the published JSON examples."""

from snusbase_client.models import (
    CountResponse,
    DomainDnsValue,
    DomainWhoisRecord,
    DomainWhoisResponse,
    IpWhoisRecord,
    IpWhoisResponse,
    SearchRequest,
    SearchResponse,
)
from snusbase_client.types import SearchType


def test_search_accepts_grouped_rows_and_a_flat_list() -> None:
    grouped = SearchResponse.model_validate(
        {
            "took": 1,
            "size": 2,
            "results": {
                "NO_EMAIL": [{"username": "ada", "host": "box"}],
                "example.com": [{"email": "ada@example.com", "extra_col": "kept"}],
            },
            "future_field": True,
        }
    )
    assert grouped.results["example.com"][0]["extra_col"] == "kept"
    assert grouped.model_dump()["future_field"] is True

    flat = SearchResponse.model_validate(
        {"took": 1.0, "size": 1, "results": [{"email": "ada@example.com"}]}
    )
    assert flat.results == [{"email": "ada@example.com"}]


def test_count_omits_results_when_the_field_is_absent() -> None:
    parsed = CountResponse.model_validate({"took": 18.591, "size": 1245})
    assert parsed.results is None
    parsed = CountResponse.model_validate({"took": 1, "size": 0, "results": {}})
    assert parsed.took == 1.0
    assert parsed.results == {}


def test_ip_whois_record_alias_and_grouping() -> None:
    parsed = IpWhoisResponse.model_validate(
        {
            "took": 6.4,
            "size": 1,
            "results": {
                "12.34.56.78": {
                    "query": "12.34.56.78",
                    "as": "AS7018 AT&T Enterprises, LLC",
                    "lat": 39.9612,
                    "mobile": False,
                }
            },
        }
    )
    record = parsed.results["12.34.56.78"]
    assert isinstance(record, IpWhoisRecord)
    assert record.as_ == "AS7018 AT&T Enterprises, LLC"
    assert record.lat == 39.9612
    assert record.mobile is False

    grouped = IpWhoisResponse.model_validate(
        {
            "took": 1,
            "size": 2,
            "results": {
                "United States": [{"country": "United States"}],
                "NO_COUNTRY": [{}],
            },
        }
    )
    assert grouped.results["NO_COUNTRY"][0].country is None

    flat = IpWhoisResponse.model_validate({"took": 1, "size": 1, "results": [{"query": "1.2.3.4"}]})
    assert isinstance(flat.results, list)
    assert flat.results[0].query == "1.2.3.4"


def test_domain_whois_mx_values_errors_and_loose_fields() -> None:
    parsed = DomainWhoisResponse.model_validate(
        {
            "took": 264.706,
            "size": 1,
            "results": {
                "example.org": {
                    "domain": "example.org",
                    "tld": "org",
                    "contact": {"abuse": {"email": "abuse@example.org"}},
                    "registrant": {"org": "Example"},
                    "meta": {"sources": ["rdap"], "source": "rdap"},
                    "dns": {
                        "security": {"signed": False},
                        "records": [
                            {
                                "type": "A",
                                "name": "example.org",
                                "ttl": 300,
                                "values": ["192.0.2.1"],
                            },
                            {
                                "type": "MX",
                                "name": "example.org",
                                "ttl": 300,
                                "values": [{"priority": 0, "server": "."}],
                            },
                        ],
                    },
                }
            },
            "errors": ["missing.test: Likely not registered"],
        }
    )
    record = parsed.results["example.org"]
    assert isinstance(record, DomainWhoisRecord)
    assert record.contact is not None
    assert record.contact["abuse"]["email"] == "abuse@example.org"
    assert record.registrant == {"org": "Example"}
    assert record.meta is not None
    assert record.meta.model_dump()["source"] == "rdap"
    assert record.dns is not None
    assert record.dns.records is not None
    mx_values = record.dns.records[1].values
    assert mx_values is not None
    assert isinstance(mx_values[0], DomainDnsValue)
    assert mx_values[0].priority == 0
    assert mx_values[0].server == "."
    a_values = record.dns.records[0].values
    assert a_values == ["192.0.2.1"]
    assert parsed.errors == ["missing.test: Likely not registered"]

    grouped = DomainWhoisResponse.model_validate(
        {"took": 1, "size": 1, "results": {"org": [{"tld": "org"}]}}
    )
    assert grouped.results["org"][0].tld == "org"
    flat = DomainWhoisResponse.model_validate(
        {"took": 1, "size": 1, "results": [{"domain": "example.org"}]}
    )
    assert isinstance(flat.results, list)


def test_search_request_omits_unset_and_keeps_false() -> None:
    minimal = SearchRequest(terms=["ada@example.com"], types=[SearchType.EMAIL])
    assert minimal.model_dump(mode="json", exclude_none=True) == {
        "terms": ["ada@example.com"],
        "types": ["email"],
    }
    explicit = SearchRequest(
        terms=["ada"],
        types=["username"],
        wildcard=False,
        group_by=False,
        tables=[],
    )
    assert explicit.model_dump(mode="json", exclude_none=True) == {
        "terms": ["ada"],
        "types": ["username"],
        "wildcard": False,
        "group_by": False,
        "tables": [],
    }
