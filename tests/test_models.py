"""Response shapes described in prose, beyond the published JSON examples."""

from typing import get_args

import pytest
from pydantic import ValidationError

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
    SearchRequest,
    SearchResponse,
    SearchType,
    SearchTypeName,
    StatsResponse,
)


@pytest.mark.parametrize(
    "model",
    [SearchResponse, ComboLookupResponse, HashLookupResponse],
)
def test_breach_responses_accept_grouped_rows_and_a_flat_list(model: type) -> None:
    grouped = model.model_validate(
        {
            "took": 1,
            "size": 2,
            "results": {
                "NO_EMAIL": [{"username": "ada", "password": "secret", "host": "box"}],
                "example.com": [{"email": "ada@example.com", "extra_col": "kept"}],
            },
            "future_field": True,
        }
    )
    assert grouped.results["example.com"][0]["extra_col"] == "kept"
    assert grouped.results["NO_EMAIL"][0]["password"] == "secret"
    assert grouped.model_dump()["future_field"] is True

    flat = model.model_validate({"took": 1.0, "size": 1, "results": [{"email": "ada@example.com"}]})
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

    without_errors = DomainWhoisResponse.model_validate({"took": 1, "size": 0, "results": {}})
    assert without_errors.errors is None

    grouped = DomainWhoisResponse.model_validate(
        {"took": 1, "size": 1, "results": {"org": [{"tld": "org"}]}}
    )
    assert grouped.results["org"][0]["tld"] == "org"
    flat = DomainWhoisResponse.model_validate(
        {"took": 1, "size": 1, "results": [{"domain": "example.org"}]}
    )
    assert flat.results == [{"domain": "example.org"}]


def test_request_models_omit_unset_and_keep_false() -> None:
    assert SearchRequest(terms=["ada@example.com"], types=[SearchType.EMAIL]).model_dump(
        mode="json", exclude_none=True
    ) == {
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
    counted = CountRequest(
        terms=["ada@example.com"],
        types=[SearchType.EMAIL],
        include_results=False,
    )
    assert counted.model_dump(mode="json", exclude_none=True) == {
        "terms": ["ada@example.com"],
        "types": ["email"],
        "include_results": False,
    }
    assert (
        CountRequest(
            terms=["ada@example.com"],
            types=[SearchType.EMAIL],
            include_results=True,
        ).model_dump(mode="json", exclude_none=True)["include_results"]
        is True
    )
    assert ComboLookupRequest(terms=["ada"], types=[ComboLookupType.USERNAME]).model_dump(
        mode="json", exclude_none=True
    ) == {"terms": ["ada"], "types": ["username"]}
    assert HashLookupRequest(
        terms=["abc"],
        types=[HashLookupType.HASH],
        wildcard=False,
        group_by=False,
    ).model_dump(mode="json", exclude_none=True) == {
        "terms": ["abc"],
        "types": ["hash"],
        "wildcard": False,
        "group_by": False,
    }
    assert IpWhoisRequest(terms=["1.2.3.4"]).model_dump(mode="json", exclude_none=True) == {
        "terms": ["1.2.3.4"]
    }
    assert IpWhoisRequest(terms=["1.2.3.4"], group_by=False).model_dump(
        mode="json", exclude_none=True
    ) == {"terms": ["1.2.3.4"], "group_by": False}
    assert DomainWhoisRequest(terms=["example.org"]).model_dump(mode="json", exclude_none=True) == {
        "terms": ["example.org"]
    }


def test_type_literals_match_the_enums() -> None:
    assert list(get_args(SearchTypeName)) == [member.value for member in SearchType]
    assert list(get_args(ComboLookupTypeName)) == [member.value for member in ComboLookupType]
    assert list(get_args(HashLookupTypeName)) == [member.value for member in HashLookupType]
    assert "phone" not in SearchType


def test_stats_keeps_unknown_fields_and_requires_features() -> None:
    parsed = StatsResponse.model_validate(
        {
            "rows": 3,
            "tables": {"T": ["email"]},
            "features": {"view_more": ["T"], "combo_lookup": [], "future": True},
            "future_top": 1,
        }
    )
    assert parsed.rows == 3
    assert parsed.features.view_more == ["T"]
    assert parsed.features.model_dump()["future"] is True
    assert parsed.model_dump()["future_top"] == 1
    with pytest.raises(ValidationError):
        StatsResponse.model_validate({"rows": 1, "tables": {}})


def test_request_models_follow_the_documented_parameters() -> None:
    assert "group_by" not in CountRequest.model_fields
    assert "include_results" in CountRequest.model_fields
    assert "include_results" not in SearchRequest.model_fields
    assert "group_by" in SearchRequest.model_fields
    assert "include_results" not in ComboLookupRequest.model_fields
    assert "group_by" in ComboLookupRequest.model_fields
    assert "include_results" not in HashLookupRequest.model_fields
    assert "group_by" in HashLookupRequest.model_fields
