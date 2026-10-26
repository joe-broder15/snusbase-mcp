"""Validate the OpenAPI document and check it against the client."""

from pathlib import Path
from typing import Any, get_args

import pytest
from pydantic import BaseModel

from snusbase_client import (
    AsyncSnusbaseClient,
    ComboLookupType,
    ComboLookupTypeName,
    HashLookupType,
    HashLookupTypeName,
    SearchType,
    SearchTypeName,
    __version__,
)
from snusbase_client.client import SnusbaseClient
from snusbase_client.endpoints import OPERATIONS
from snusbase_client.models import (
    ComboLookupRequest,
    ComboLookupResponse,
    CountRequest,
    CountResponse,
    DomainWhoisRequest,
    DomainWhoisResponse,
    HashLookupRequest,
    HashLookupResponse,
    IpWhoisRequest,
    IpWhoisResponse,
    SearchRequest,
    SearchResponse,
    StatsResponse,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT / "openapi" / "snusbase.yaml"

RESPONSE_MODELS: dict[tuple[str, str], type[BaseModel]] = {
    ("get", "/data/stats"): StatsResponse,
    ("post", "/data/search"): SearchResponse,
    ("post", "/data/count"): CountResponse,
    ("post", "/tools/combo-lookup"): ComboLookupResponse,
    ("post", "/tools/hash-lookup"): HashLookupResponse,
    ("post", "/tools/ip-whois"): IpWhoisResponse,
    ("post", "/tools/domain-whois"): DomainWhoisResponse,
}

REQUEST_MODELS: dict[str, type[BaseModel]] = {
    "/data/search": SearchRequest,
    "/data/count": CountRequest,
    "/tools/combo-lookup": ComboLookupRequest,
    "/tools/hash-lookup": HashLookupRequest,
    "/tools/ip-whois": IpWhoisRequest,
    "/tools/domain-whois": DomainWhoisRequest,
}


def load_spec() -> dict[str, Any]:
    from openapi_spec_validator.readers import read_from_filename

    spec, _ = read_from_filename(str(SPEC_PATH))
    return spec


def _validate(spec: dict[str, Any]) -> None:
    from openapi_spec_validator import validate

    validate(spec)


def _public_methods(cls: type) -> set[str]:
    return {
        name for name, value in vars(cls).items() if callable(value) and not name.startswith("_")
    }


def _examples(media: dict[str, Any]) -> list[Any]:
    found: list[Any] = []
    if "example" in media:
        found.append(media["example"])
    for example in media.get("examples", {}).values():
        if "value" in example:
            found.append(example["value"])
    return found


@pytest.fixture(scope="module")
def spec() -> dict[str, Any]:
    loaded = load_spec()
    _validate(loaded)
    return loaded


def test_spec_file_validates() -> None:
    _validate(load_spec())


def test_paths_and_methods_match_the_client(spec: dict[str, Any]) -> None:
    documented: set[tuple[str, str]] = set()
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if method.startswith("x-") or method == "parameters":
                continue
            documented.add((method.upper(), path))
            assert operation["operationId"]
    expected = {(method, path) for method, path in OPERATIONS.values()}
    assert documented == expected
    assert _public_methods(SnusbaseClient) == set(OPERATIONS) | {"close"}
    assert _public_methods(AsyncSnusbaseClient) == set(OPERATIONS) | {"aclose"}


def test_auth_scheme_and_stats_opt_out(spec: dict[str, Any]) -> None:
    scheme = spec["components"]["securitySchemes"]["Auth"]
    assert scheme == {
        "type": "apiKey",
        "in": "header",
        "name": "Auth",
        "description": scheme["description"],
    }
    assert spec["security"] == [{"Auth": []}]
    stats = spec["paths"]["/data/stats"]["get"]
    assert stats["security"] == []
    assert "headers" not in stats["responses"]["200"]
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if path == "/data/stats" and method == "get":
                continue
            if method.startswith("x-"):
                continue
            assert operation["security"] == [{"Auth": []}]
            success = operation["responses"]["200"]
            assert set(success["headers"]) == {
                "X-Rate-Limit",
                "X-Rate-Limit-Remaining",
                "X-Rate-Limit-Reset",
            }


def test_rate_limit_headers_on_authenticated_errors(spec: dict[str, Any]) -> None:
    bad = spec["components"]["responses"]["BadRequest"]
    assert set(bad["headers"]) == {
        "X-Rate-Limit",
        "X-Rate-Limit-Remaining",
        "X-Rate-Limit-Reset",
    }
    reset = spec["components"]["headers"]["XRateLimitReset"]["description"]
    assert "Seconds until" in reset
    bare = spec["components"]["responses"]["RateLimitedWithoutRateLimit"]
    assert "headers" not in bare


def test_type_enums_match_the_spec_and_literals(spec: dict[str, Any]) -> None:
    schemas = spec["components"]["schemas"]
    assert schemas["SearchType"]["enum"] == [member.value for member in SearchType]
    assert schemas["ComboLookupType"]["enum"] == [member.value for member in ComboLookupType]
    assert schemas["HashLookupType"]["enum"] == [member.value for member in HashLookupType]
    assert list(get_args(SearchTypeName)) == [member.value for member in SearchType]
    assert list(get_args(ComboLookupTypeName)) == [member.value for member in ComboLookupType]
    assert list(get_args(HashLookupTypeName)) == [member.value for member in HashLookupType]
    assert "phone" not in schemas["SearchType"]["enum"]


def test_parameter_shapes(spec: dict[str, Any]) -> None:
    schemas = spec["components"]["schemas"]
    assert "group_by" not in schemas["CountRequest"]["properties"]
    assert schemas["CountRequest"]["properties"]["include_results"]["default"] is True
    assert "include_results" not in schemas["SearchRequest"]["properties"]
    assert schemas["SearchGroupBy"]["default"] == "db"
    assert "default" not in schemas["WhoisGroupBy"]
    assert schemas["DomainWhoisRequest"]["properties"]["terms"]["maxItems"] == 100
    assert "maxItems" not in schemas["SearchRequest"]["properties"]["terms"]
    assert schemas["BreachRecord"]["additionalProperties"] is True
    assert schemas["CountResults"]["additionalProperties"] == {"type": "integer"}
    tables = schemas["StatsResponse"]["properties"]["tables"]
    assert tables["additionalProperties"]["type"] == "array"


def test_documented_examples_match_client_models(spec: dict[str, Any]) -> None:
    seen_response = set()
    seen_request = set()
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if method.startswith("x-") or method == "parameters":
                continue
            if "requestBody" in operation:
                media = operation["requestBody"]["content"]["application/json"]
                examples = _examples(media)
                assert examples, path
                model = REQUEST_MODELS[path]
                for example in examples:
                    model.model_validate(example)
                seen_request.add(path)
            media = operation["responses"]["200"]["content"]["application/json"]
            examples = _examples(media)
            assert examples, (method, path)
            model = RESPONSE_MODELS[(method, path)]
            for example in examples:
                model.model_validate(example)
            seen_response.add((method, path))
    assert seen_response == set(RESPONSE_MODELS)
    assert seen_request == set(REQUEST_MODELS)


def test_package_version_matches_pyproject() -> None:
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["version"] == __version__
    assert project["name"] == "snusbase-client"
