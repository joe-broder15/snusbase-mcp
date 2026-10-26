"""Errors raised by the Snusbase client.

HTTP 400, 401, and 429 map to the specific subclasses. Any other HTTP failure,
transport failure, or successful body that does not match the documented shape
maps to :class:`SnusbaseAPIError`. A missing or blank API key is
:class:`SnusbaseAuthError` and is raised before a request is sent.
"""

from collections.abc import Sequence

from snusbase_client.ratelimit import RateLimit


class SnusbaseError(Exception):
    """Base class for errors from this client."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        errors: Sequence[str] = (),
        rate_limit: RateLimit | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.errors = list(errors)
        self.rate_limit = rate_limit if rate_limit is not None else RateLimit()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status_code={self.status_code!r}, errors={self.errors!r})"


class SnusbaseBadRequestError(SnusbaseError):
    """HTTP 400, or a request body that fails local checks against the docs."""


class SnusbaseAuthError(SnusbaseError):
    """HTTP 401, or no API key was configured for an authenticated endpoint."""


class SnusbaseRateLimitError(SnusbaseError):
    """HTTP 429.

    ``reset_seconds`` is ``X-Rate-Limit-Reset`` when that header is an integer.
    The docs define it as seconds until the window resets, not a Unix timestamp.
    """

    def __init__(
        self,
        message: str,
        *,
        reset_seconds: int | None,
        status_code: int | None = 429,
        errors: Sequence[str] = (),
        rate_limit: RateLimit | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            errors=errors,
            rate_limit=rate_limit,
        )
        self.reset_seconds = reset_seconds


class SnusbaseAPIError(SnusbaseError):
    """Any other failed response, including transport errors and unexpected redirects."""
