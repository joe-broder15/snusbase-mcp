# snusbase-mcp

Snusbase MCP for your agent to be an OPSEC DEMON.

Typed Python client for the public [Snusbase API](https://docs.snusbase.com/).

The HTTP client lives in `src/snusbase_client`. The MCP server lives in `src/snusbase_mcp` and exposes two tools, `whois` and `search`.

The client follows the public docs and the [source mirror](https://github.com/snusbase/docs.snusbase.com). It does not add endpoints, parameters, or fields those docs do not describe. This is not an official Snusbase library. No API key is stored in this repository.

## Safety

`POST /data/search`, `POST /tools/combo-lookup`, and `POST /tools/hash-lookup` can return plaintext passwords and other credentials.

Snusbase does not meaningfully sanitize imported breach data. Rows may contain HTML or exploit payloads that were aimed at the third-party sites the data came from. Treat every field as untrusted. Do not render results as HTML. Do not log raw rows.

You are responsible for complying with the Snusbase Terms of Service: <https://docs.snusbase.com/terms-of-service.html>.

Keep the activation code in `SNUSBASE_API_KEY` or another secret store. The client reads that variable, or a constructor argument. `repr` and `str` on the client redact the code, and the package does not log it. `GET /data/stats` does not send the `Auth` header.

## Install

Python 3.12. [uv](https://docs.astral.sh/uv/) manages the environment. Runtime dependencies are httpx, pydantic v2, and the official `mcp` SDK. pytest, respx, and ruff are in the `dev` dependency group.

```bash
uv sync --group dev
export SNUSBASE_API_KEY='sbYOUR_ACTIVATION_CODE'
```

Codes issued after September 2021 start with `sb` plus 28 characters. The client does not check that shape.

`uv sync` installs this checkout. From another project, `uv add --editable /path/to/this/checkout` installs the `snusbase-client` distribution. Import it as `snusbase_client`.

## MCP server

`snusbase-mcp` speaks MCP over stdio. The agent sees two tools:

- `whois` takes IP addresses and domain names in one list. A value that `ipaddress.ip_address` accepts is sent to IP WHOIS. Anything else is sent as a domain. `group_by` is left unset, so records stay keyed by the term you sent. A domain response can include per-name errors. More than 100 domains is rejected before a request is sent.
- `search` calls `POST /data/search` with `terms` and `types` only (`email`, `username`, `lastip`, `password`, `hash`, `name`, `_domain`). Results stay grouped by database. Every row field is untrusted and can contain a leaked password.

Combo lookup, hash lookup, count, and stats stay on the client. They are not tools. The activation code is read from `SNUSBASE_API_KEY`. It is not a tool argument. A rate-limit error includes `reset_seconds` so the agent can wait.

```bash
export SNUSBASE_API_KEY='sbYOUR_ACTIVATION_CODE'
uv run snusbase-mcp
```

Point the agent at that command.

## Usage

`count` reports how many rows match without returning the rows. Prefer it when you only need to know whether an address is exposed.

```python
import asyncio

from snusbase_client import (
    SearchType,
    SnusbaseClient,
    SnusbaseRateLimitError,
)


async def main() -> None:
    async with SnusbaseClient() as client:
        stats = await client.stats()
        print(stats.data.rows, len(stats.data.tables))

        try:
            counted = await client.count(["me@example.com"], [SearchType.EMAIL])
        except SnusbaseRateLimitError as exc:
            print("retry after", exc.reset_seconds, "seconds")
        else:
            print(counted.data.size, counted.rate_limit.remaining)


asyncio.run(main())
```

Search returns the rows. With the default `group_by` of `"db"`, `results` is a dict of table name to a list of row dicts. `group_by=False` asks the server to disable grouping; the published examples do not show that JSON, and the client also accepts a bare list.

```python
async def search() -> None:
    async with SnusbaseClient() as client:
        found = await client.search(
            ["me@example.com"],
            [SearchType.EMAIL, SearchType.USERNAME],
        )
        results = found.data.results
        if isinstance(results, dict):
            for table, rows in results.items():
                print(table, len(rows))

        whois = await client.domain_whois(["example.org"])
        print(whois.data.size, whois.data.errors)
```

| Method | Request | Auth header |
| --- | --- | --- |
| `stats` | `GET /data/stats` | omitted |
| `search` | `POST /data/search` | `Auth` |
| `count` | `POST /data/count` | `Auth` |
| `combo_lookup` | `POST /tools/combo-lookup` | `Auth` |
| `hash_lookup` | `POST /tools/hash-lookup` | `Auth` |
| `ip_whois` | `POST /tools/ip-whois` | `Auth` |
| `domain_whois` | `POST /tools/domain-whois` | `Auth` |

`search` and `count` types are `email`, `username`, `lastip`, `password`, `hash`, `name`, and `_domain` (`SearchType.DOMAIN`). Combo types are `username` and `password`. Hash types are `hash` and `password`. Domain WHOIS accepts at most 100 names per call. A domain WHOIS HTTP 200 can still include `data.errors` for names that did not resolve.

Optional arguments that you leave as `None` are omitted from the JSON body, so the server applies its defaults (`group_by` of `"db"` on search, combo, and hash; `include_results` of true on count). Pass `False` when you want the JSON boolean `false`. IP and domain WHOIS do not default `group_by` to `"db"`: omitting it keys `results` by the input.

`base_url` defaults to `https://api.snusbase.com`. `timeout` defaults to 60 seconds and is passed to httpx. Redirects are not followed.

Each call returns `SnusbaseResponse`. `data` is the parsed body. `rate_limit` is the documented headers (`limit`, `remaining`, `reset_seconds`). On HTTP 429, `SnusbaseRateLimitError.reset_seconds` is that same reset value. The docs define it as seconds until the window resets.

| Exception | When |
| --- | --- |
| `SnusbaseBadRequestError` | HTTP 400, or the local body does not match the documented parameters |
| `SnusbaseAuthError` | HTTP 401, or an authenticated call was made with no key configured |
| `SnusbaseRateLimitError` | HTTP 429 |
| `SnusbaseAPIError` | Any other HTTP failure, a transport error, an unexpected redirect, or a 2xx body that does not match the documented shape |

Documented limits, which Snusbase says can change (trust the headers when they disagree):

- `/data/search` and `/data/count`: 2048 requests every 12 hours
- `/tools/combo-lookup`: 4096 requests every 12 hours
- Every other endpoint, including stats, hash lookup, and both WHOIS calls: 256 requests every 2 minutes

The marketing homepage says paying members get up to 2048 API requests per day. This client follows the API docs above, not that sentence.

## Development

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
```

CI (`.github/workflows/ci.yml`) installs Nix and runs `nix flake check`, which is the single CI gate (ruff check + format, and pytest on Python 3.12).

### Nix

`flake.nix` provides a Python 3.12 + uv shell (`UV_PYTHON_DOWNLOADS=never`). uv installs the locked dependencies from PyPI. `nix flake check` and `nix build` use [uv2nix](https://pyproject-nix.github.io/uv2nix/) so checks and the default package match `uv.lock` (including the `dev` dependency group for pytest and ruff).

```bash
nix develop
uv sync --group dev
uv run pytest
uv run ruff check
```

Without entering the shell:

```bash
nix develop -c uv run pytest
```

```bash
nix flake check
nix build
```

If your Nix still treats flakes as experimental:

```bash
nix --extra-experimental-features 'nix-command flakes' flake check
```

## Layout

```
src/snusbase_client/     import snusbase_client
src/snusbase_mcp/        snusbase-mcp stdio server
tests/                   pytest, respx
pyproject.toml           project metadata and the uv dev dependency group
uv.lock
flake.nix
flake.lock
```

## Notes on the upstream docs

These are ambiguities in the public docs as of the mirror README blob `535876c681d42db603e3f2fe72e6f13cb4e94542`. The client models follow the choices below.

- The [homepage](https://snusbase.com/) says the API is included up to 2048 requests per day. The API docs say search and count are 2048 every 12 hours, combo lookup is 4096 every 12 hours, and other endpoints are 256 every 2 minutes.
- `GET /data/stats` is documented as not requiring authentication, and its request example has no `Auth` header. The JavaScript and Python samples send `Auth` on every call, including stats, because the helper always sets the header. This client omits `Auth` on stats. Rate-limit headers are documented for authenticated requests. The client still reads them if a stats response includes them.
- `took` is a number in every example. The docs never say whether it is seconds, milliseconds, or another unit.
- Search, combo, and hash say `group_by: false` disables grouping, and that a row missing the grouped column is appended to a `NO_{GROUP_BY}` object. They do not show that JSON. Whois docs are explicit: omit `group_by` for an object keyed by the input, pass a field name for arrays plus a `NO_{FIELD}` bucket, and pass `false` for a flat array. The client accepts an object of row arrays or a list for search, combo, and hash, and the three whois shapes.
- Domain `group_by` examples mention `registrant.org` and `meta.source`. The sample record has `contact` and `meta.sources`. Rows are plain dicts, so both names are kept.
- There is no documented phone search type. The search types are `email`, `username`, `lastip`, `password`, `hash`, `name`, and `_domain`.
- Activation codes after September 2021 are `sb` plus 28 characters. The alphabet is not specified, and older codes are not described.
- The "search specific tables" example uses `0001_STEALERLOGS_NA_106M_MALWARE_2023`. The stats example uses `0001_STEALERLOGS_NA_121M_MALWARE_2023`. Both are copied as published.
- HTTP 400, 401, and 429 are documented as an `errors` array, and those messages are safe to show to end users. No sample error JSON is published. The only sample `errors` value is on a 200 domain-whois body (`not8489291real.com: Likely not registered`).
- `X-Rate-Limit-Reset` is documented as seconds until the window resets, not as a Unix timestamp.
- Wildcard syntax (`%`, `?`, no leading wildcard, backslash escapes) is written up on the search page. Combo and hash only say that `wildcard` enables wildcard search.

## License

MIT. See [LICENSE](LICENSE).
