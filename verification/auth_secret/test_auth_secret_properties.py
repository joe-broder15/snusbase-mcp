"""Property checks for activation-code redaction and Auth-header discipline.

These tests call the real functions in ``snusbase_client.client``. They are not a
hand model of the client. Hypothesis generates keys and request shapes so that a
single fixed-key unit test cannot paper over a leak.

Run (from repo root, after ``uv sync --group verification --group dev``):

    uv run --group verification pytest verification/auth_secret -q
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from snusbase_client.client import (
    AUTH_HEADER,
    OPERATIONS,
    SnusbaseClient,
    _client_repr,
    _request_kwargs,
    _resolve_api_key,
    _Secret,
)
from snusbase_client.exceptions import SnusbaseAuthError

# Bound: non-empty Unicode text up to 64 code points. Documented activation codes
# are ~30 ASCII chars; we overshoot so a length- or charset-specific leak still
# fails. Null bytes are excluded so header maps stay well-defined for httpx.
_key = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=64,
).filter(lambda s: s.strip() != "")

_blank = st.text(
    alphabet=st.sampled_from(" \t\n\r"),
    min_size=1,
    max_size=8,
)

_json_body = st.one_of(
    st.none(),
    st.just({"terms": ["example"], "types": ["email"]}),
)

_settings = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@_settings
@given(key=_key)
def test_secret_renders_only_the_redaction_marker(key: str) -> None:
    """Property: _Secret always renders the fixed redaction marker, never the key.

    Harm: a key that shows up in str/repr/format lands in logs and crash reports.
    """
    secret = _Secret(key)
    assert secret.reveal() == key
    # Exact marker equality is the property: any key-shaped leak changes these
    # strings. Substring checks are not used — keys like "<" collide with the
    # marker text without being a leak.
    assert repr(secret) == "_Secret(<redacted>)"
    assert str(secret) == "<redacted>"
    assert format(secret) == "<redacted>"
    assert format(secret, "s") == "<redacted>"


@_settings
@given(key=_key)
def test_client_repr_uses_api_key_set_flag_only(key: str) -> None:
    """Property: SnusbaseClient str/repr expose only api_key_set, never the key."""
    client = SnusbaseClient(api_key=key)
    try:
        expected = (
            f"SnusbaseClient(base_url={client.base_url!r}, "
            f"timeout={client.timeout!r}, api_key_set=True)"
        )
        assert repr(client) == expected
        assert str(client) == expected
        assert (
            _client_repr("SnusbaseClient", client.base_url, client.timeout, client._api_key)
            == expected
        )
        if key not in expected:
            assert key not in repr(client)
    finally:
        asyncio.run(client.aclose())


@_settings
@given(key=_key, json_body=_json_body)
def test_unauthenticated_kwargs_omit_auth(key: str, json_body: dict[str, Any] | None) -> None:
    """Property: authenticated=False never attaches Auth, even when a key is set.

    Harm: stats is documented as unauthenticated; putting Auth on that call can
    leak the activation code into access logs that treat stats as public.
    """
    secret = _Secret(key)
    kwargs = _request_kwargs(secret, json_body=json_body, authenticated=False)
    assert "headers" not in kwargs
    if json_body is not None:
        assert kwargs.get("json") == json_body
    else:
        assert "json" not in kwargs


@_settings
@given(key=_key, json_body=_json_body)
def test_authenticated_kwargs_send_exact_key(key: str, json_body: dict[str, Any] | None) -> None:
    """Property: authenticated=True with a key sets Auth to that exact key."""
    secret = _Secret(key)
    kwargs = _request_kwargs(secret, json_body=json_body, authenticated=True)
    headers = kwargs["headers"]
    assert headers[AUTH_HEADER] == key
    assert headers["Content-Type"] == "application/json"
    if json_body is not None:
        assert kwargs.get("json") == json_body
    else:
        assert "json" not in kwargs


@_settings
@given(json_body=_json_body)
def test_authenticated_kwargs_require_a_key(json_body: dict[str, Any] | None) -> None:
    """Property: authenticated=True with no key raises before headers are built."""
    with pytest.raises(SnusbaseAuthError):
        _request_kwargs(None, json_body=json_body, authenticated=True)


@_settings
@given(blank=_blank)
def test_blank_constructor_key_is_rejected(blank: str) -> None:
    """Property: empty/whitespace constructor keys raise SnusbaseAuthError."""
    with pytest.raises(SnusbaseAuthError):
        _resolve_api_key(blank)


def test_only_stats_disables_auth_in_source() -> None:
    """Structural: every public operation except stats calls with authenticated=True.

    The Auth-header properties above are only as strong as the call sites that
    pass ``authenticated``. This check fails if a new or existing method wires
    the flag the wrong way.
    """
    for name in OPERATIONS:
        method = getattr(SnusbaseClient, name)
        source = inspect.getsource(method)
        if name == "stats":
            assert "authenticated=False" in source
            assert "authenticated=True" not in source
        else:
            assert "authenticated=True" in source
            assert "authenticated=False" not in source
