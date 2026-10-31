# Change this repository

`snusbase-client` is one async client, `SnusbaseClient`, for the seven documented Snusbase endpoints. The Pydantic models are the contract. This repository has no OpenAPI file.

Read [Notes on the upstream docs](README.md#notes-on-the-upstream-docs) before you change a request field or a response field. Do not add an endpoint, a parameter, a field, or a search type that the public docs do not describe. Do not change the published table name in `tests/test_client.py` or in those notes. The docs published two different names, and the client keeps both.

## Run the check CI runs

`.github/workflows/ci.yml` runs one command. `requires-python` is `>=3.12,<3.13`. Do not widen that range.

```bash
nix flake check -L
```

`tests/test_agent_contract.py` fails if this file drops that command or the `requires-python` value.

`nix flake check` runs `ruff check`, `ruff format --check`, and pytest from the `uv.lock` environment, on Python 3.12. On a machine without Nix, this stand-in uses the same lockfile. It is not the CI command.

```bash
uv sync --frozen --group dev
uv run ruff check
uv run ruff format --check
uv run pytest
```

## Keep the documented behavior

Request models in `models.py` reject unknown fields. Response models keep extra keys. `None` on an optional request field is left out of the JSON. `False` and an empty list are sent. Do not fill in `group_by` with `"db"` inside the client. For IP WHOIS and domain WHOIS, a missing `group_by` means results keyed by the input.

`stats` does not send the `Auth` header, even when a key is set. A blank `api_key` argument raises at construction. A missing or blank `SNUSBASE_API_KEY` means there is no key, so `stats` still runs.

The client sets `follow_redirects=False`. A redirect must not carry `Auth` to another host. The redirect error must not include the `Location` header.

`_Secret` hides the activation code from `str` and `repr`. `reveal` is the only way to read it. A transport error names the exception type and is raised `from None`. Do not put an `httpx.Response` or an `httpx.Request` on `SnusbaseResponse` or on an exception.

This package does not log. Breach rows are untrusted. Do not log a row, and do not render a row as HTML.

There is no blocking client. Do not add one beside `SnusbaseClient`. The client does not retry, and it does not sleep on HTTP 429. It raises `SnusbaseRateLimitError` and leaves the retry to the caller.

`client.py` owns `OPERATIONS`, the paths, the header name, the key, and `parse_rate_limit`. `models.py` owns the request models, the response models, and the wire enums.

## Change a dependency

Edit `pyproject.toml`, then run `uv lock`. `flake.nix` loads that lockfile through uv2nix. Do not add the package to a hand-written Nix list. Add a build override in `flake.nix` only when a locked dependency fails to build.

## Leave the MCP server for a task that asks for it

`src/snusbase_client/__init__.py` reserves `src/snusbase_mcp`. The server is not in this repository. Do not add that package unless the task asks for the server. Hatchling packages `src/snusbase_client` only, until the build configuration names another package.
