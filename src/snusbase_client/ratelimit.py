"""Parse the documented Snusbase rate-limit response headers."""

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict


class RateLimit(BaseModel):
    """Rate-limit headers from one response.

    Documented on authenticated requests:

    - ``X-Rate-Limit`` -> ``limit``
    - ``X-Rate-Limit-Remaining`` -> ``remaining``
    - ``X-Rate-Limit-Reset`` -> ``reset_seconds`` (seconds until the window resets)

    Missing or non-integer header values are ``None``. ``GET /data/stats`` is
    unauthenticated, so these are typically absent on that call.
    """

    model_config = ConfigDict(extra="forbid")

    limit: int | None = None
    remaining: int | None = None
    reset_seconds: int | None = None


def parse_rate_limit(headers: Mapping[str, str]) -> RateLimit:
    """Read rate-limit headers. Lookup is case-insensitive."""

    def optional_int(name: str) -> int | None:
        target = name.lower()
        for key, value in headers.items():
            if key.lower() != target:
                continue
            raw = value.strip()
            if raw == "":
                return None
            try:
                return int(raw)
            except ValueError:
                return None
        return None

    return RateLimit(
        limit=optional_int("X-Rate-Limit"),
        remaining=optional_int("X-Rate-Limit-Remaining"),
        reset_seconds=optional_int("X-Rate-Limit-Reset"),
    )
