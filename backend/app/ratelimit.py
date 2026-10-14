"""slowapi rate limiting: strict on /auth/login, sane default on read routes."""

from __future__ import annotations

import typing
from collections.abc import Callable
from typing import TypeVar

from slowapi import Limiter
from slowapi.util import get_remote_address

LOGIN_LIMIT = "5/minute"
READ_LIMIT = "120/minute"

limiter = Limiter(key_func=get_remote_address, headers_enabled=True)

_Call = TypeVar("_Call", bound=Callable[..., object])


def resolve_annotations(func: _Call) -> _Call:
    """Materialize PEP 563 string annotations into real objects before wrapping.

    slowapi wraps endpoints in a function defined in its own module, and FastAPI
    resolves string annotations against the wrapper's globals, where endpoint
    types (models, dependencies) do not exist. Resolving eagerly against the
    endpoint's own module globals keeps every annotation intact: functools.wraps
    copies the real-object __annotations__ onto the wrapper unchanged.
    """
    func.__annotations__ = typing.get_type_hints(func, include_extras=True)
    return func
