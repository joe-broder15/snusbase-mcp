"""Search and lookup type enums from the Snusbase API docs.

The string values are the wire values. ``SearchType.DOMAIN`` is ``_domain``.
"""

from enum import StrEnum
from typing import Literal


class SearchType(StrEnum):
    """``types`` values for ``POST /data/search`` and ``POST /data/count``."""

    EMAIL = "email"
    USERNAME = "username"
    LASTIP = "lastip"
    PASSWORD = "password"
    HASH = "hash"
    NAME = "name"
    DOMAIN = "_domain"


SearchTypeName = Literal[
    "email",
    "username",
    "lastip",
    "password",
    "hash",
    "name",
    "_domain",
]


class ComboLookupType(StrEnum):
    """``types`` values for ``POST /tools/combo-lookup``."""

    USERNAME = "username"
    PASSWORD = "password"


ComboLookupTypeName = Literal["username", "password"]


class HashLookupType(StrEnum):
    """``types`` values for ``POST /tools/hash-lookup``."""

    HASH = "hash"
    PASSWORD = "password"


HashLookupTypeName = Literal["hash", "password"]
