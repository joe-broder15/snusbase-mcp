---
name: verify-auth-secret
description: >-
  Verify that snusbase_client never leaks the activation code through str/repr/format
  and that Auth headers follow the authenticated flag (stats omits Auth; other calls
  send the exact key or raise). Use when changing client.py secret handling, request
  kwargs, Auth headers, stats auth, OPERATIONS, or SnusbaseClient repr — or after any
  edit under src/snusbase_client/client.py that touches those paths.
---

# Verify auth secret + Auth-header discipline

## Property (plain words)

The activation code never appears in `str` / `repr` / `format` of `_Secret` or `SnusbaseClient`. Unauthenticated calls (stats) never get an `Auth` header even when a key is configured. Authenticated calls send that exact key as `Auth`, or raise `SnusbaseAuthError` before headers are built if no key is set. Only `stats` disables auth at the call site.

## Harm if broken

An activation code in logs, crash dumps, or chat-facing `repr` is a credential leak. Putting `Auth` on `GET /data/stats` can put that credential into access logs that treat stats as public. Omitting `Auth` on paid endpoints, or sending the wrong value, breaks callers and can confuse rate-limit accounting.

## When this skill applies

Run these checks if the change touches any of:

- `src/snusbase_client/client.py` — especially `_Secret`, `_resolve_api_key`, `_request_kwargs`, `_client_repr`, `SnusbaseClient.__repr__` / `__str__`, `stats`, any method that passes `authenticated=`, or `OPERATIONS` / `AUTH_HEADER`
- `src/snusbase_client/exceptions.py` — only if `SnusbaseAuthError` construction changes how messages are formed from secrets (today it does not take the key)
- `verification/auth_secret/` or this skill

If the change is elsewhere (models-only, flake, README), you do not need this check unless you also edited the paths above.

## Tool and why

**Hypothesis** property tests against the **real** functions in `snusbase_client.client` (not a hand-written model of them).

No installable industrial verifier fits this Python surface for “arbitrary key string never appears in renderings / unauthenticated kwargs.” SMT/CrossHair are a poor fit for string non-containment over Unicode keys. Generated-input testing of the real code is the honest choice here.

Pinned via the `verification` dependency group in `pyproject.toml` (`hypothesis`).

## Bounds and assumptions

- Keys: non-empty Unicode strings up to 64 code points, no null bytes, not whitespace-only. Documented Snusbase codes are shorter ASCII; the bound is larger on purpose.
- `_request_kwargs` is checked with `json_body` either `None` or one fixed search body that does not embed the key.
- Call-site discipline (`authenticated=True`/`False`) is checked by reading each public method’s source text for those literals — not by sending HTTP.
- Does **not** cover: httpx logging of request headers at DEBUG, OS environment dumps, debugger watch windows, MCP server code (not in this tree), whether upstream Snusbase logs `Auth`, or concurrent clients sharing one key object.
- A pass means: within these bounds, the real functions satisfy the properties. It is not a proof about the whole process or every future call site.

## Coverage record

| Check | Code covered |
| --- | --- |
| Redaction marker | `_Secret.__repr__`, `__str__`, `__format__`, `reveal` |
| Client rendering | `SnusbaseClient.__repr__`, `__str__`, `_client_repr`, constructor key wrap via `_resolve_api_key` + `_Secret` |
| Auth omitted when unauthenticated | `_request_kwargs` with `authenticated=False` |
| Auth exact when authenticated | `_request_kwargs` with `authenticated=True` and a `_Secret` |
| Auth required | `_request_kwargs` with `authenticated=True` and `api_key=None` → `SnusbaseAuthError` |
| Blank constructor key | `_resolve_api_key` on whitespace-only strings |
| Call sites | Every `SnusbaseClient` method named in `OPERATIONS` (`stats` must use `authenticated=False`; all others `authenticated=True`) |

**Sync commit:** `16f1fcf75d6ef21055f17be807f6368b2c431658` (verification harness + skill; covered client code last confirmed to match these checks).

Move this sync commit forward **only after** you confirm the verification still describes the code at the new commit (re-read covered functions, rerun, and — if you changed the harness or properties — show a scratch break still fails). Do not bump it just because product tests passed.

## How to run

From the repo root:

```bash
uv sync --group verification --group dev
uv run --group verification pytest verification/auth_secret -q
```

Expect exit code 0 and all tests passed. Typical runtime is a few seconds.

You do **not** need to know Hypothesis to trust a green run: green means every property above held for the generated cases in this run under the stated bounds. Red means at least one property failed; read the failing assert and the Hypothesis `Falsifying example` block — that example is a concrete key or body in the code’s own terms.

## Reading a failure: bug vs modeling error

1. Open the failing test name and the `Falsifying example` (the generated `key` / `json_body` / `blank`).
2. Replay that example against the real function in a REPL or a one-off assert (same imports as the test file).
3. **Bug in product code** if the real function misbehaves on that input (leaks the key, attaches `Auth` when `authenticated=False`, wrong `Auth` value, fails to raise, or a call site flipped `authenticated=`). Report it; do **not** weaken the property to pass. Prefer leaving the finding.
4. **Modeling / harness error** if the example cannot occur in real use because the harness assumed something the code no longer does (e.g. `_request_kwargs` gained a required argument, redaction marker intentionally changed and docs/tests say so, or `OPERATIONS` was renamed and the structural check’s literals are stale). Fix the harness or property to match the new code’s promise, cite the evidence that the promise changed, then rerun. Show a scratch break still fails before calling it done.
5. If unsure, prefer classifying as a **bug candidate** and ask a human before relaxing a property.

## After an intentional change to covered code

1. Update `verification/auth_secret/test_auth_secret_properties.py` so every step still points at real functions and names.
2. Rerun the command above.
3. Prove the check can still fail: temporarily break one promise in `client.py` (for example make `_Secret.__repr__` return the raw value, or pass `authenticated=True` from `stats`), confirm the suite goes red, then revert the scratch break.
4. Only then set **Sync commit** in this skill to the commit that contains the updated verification + matching product code.

## Upkeep

When covered code changed without this skill, use `/maintain-formal-verification-skill`.
