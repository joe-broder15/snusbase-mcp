"""Response shapes described in prose, beyond the published JSON examples."""

from typing import get_args

from snusbase_client.models import (
    ComboLookupRequest,
    ComboLookupType,
    ComboLookupTypeName,
    CountRequest,
    CountResponse,
    DomainWhoisResponse,
    HashLookupRequest,
    HashLookupType,
    HashLookupTypeName,
    IpWhoisResponse,
    SearchRequest,
    SearchResponse,
    SearchType,
    SearchTypeName,
)


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


def test_ip_whois_keeps_raw_rows() -> None:
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
    assert record["as"] == "AS7018 AT&T Enterprises, LLC"
    assert record["lat"] == 39.9612
    assert record["mobile"] is False

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
    assert grouped.results["NO_COUNTRY"][0] == {}

    flat = IpWhoisResponse.model_validate({"took": 1, "size": 1, "results": [{"query": "1.2.3.4"}]})
    assert flat.results == [{"query": "1.2.3.4"}]


def test_domain_whois_keeps_raw_rows_and_errors() -> None:
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
    assert record["contact"]["abuse"]["email"] == "abuse@example.org"
    assert record["registrant"] == {"org": "Example"}
    assert record["meta"]["source"] == "rdap"
    mx = record["dns"]["records"][1]["values"][0]
    assert mx["priority"] == 0
    assert mx["server"] == "."
    assert record["dns"]["records"][0]["values"] == ["192.0.2.1"]
    assert parsed.errors == ["missing.test: Likely not registered"]

    grouped = DomainWhoisResponse.model_validate(
        {"took": 1, "size": 1, "results": {"org": [{"tld": "org"}]}}
    )
    assert grouped.results["org"][0]["tld"] == "org"
    flat = DomainWhoisResponse.model_validate(
        {"took": 1, "size": 1, "results": [{"domain": "example.org"}]}
    )
    assert flat.results == [{"domain": "example.org"}]


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


def test_type_literals_match_the_enums() -> None:
    assert list(get_args(SearchTypeName)) == [member.value for member in SearchType]
    assert list(get_args(ComboLookupTypeName)) == [member.value for member in ComboLookupType]
    assert list(get_args(HashLookupTypeName)) == [member.value for member in HashLookupType]
    assert "phone" not in SearchType


def test_request_models_follow_the_documented_parameters() -> None:
    assert "group_by" not in CountRequest.model_fields
    assert "include_results" in CountRequest.model_fields
    assert "include_results" not in SearchRequest.model_fields
    assert "group_by" in SearchRequest.model_fields
    assert "include_results" not in ComboLookupRequest.model_fields
    assert "group_by" in ComboLookupRequest.model_fields
    assert "include_results" not in HashLookupRequest.model_fields
    assert "group_by" in HashLookupRequest.model_fields
