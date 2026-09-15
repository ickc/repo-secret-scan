"""Name -> implementation registries for pluggable pipeline components.

Components are plain classes whose constructor keyword arguments are their
options, so a TOML table like ``[scanner.trufflehog] concurrency = 4`` maps
directly onto ``TrufflehogScanner(concurrency=4)``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class UnknownComponentError(KeyError):
    pass


class Registry(Generic[T]):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._factories: dict[str, Callable[..., T]] = {}

    def register(self, name: str) -> Callable[[Callable[..., T]], Callable[..., T]]:
        def decorator(factory: Callable[..., T]) -> Callable[..., T]:
            if name in self._factories:
                raise ValueError(f"{self.kind} {name!r} is already registered")
            self._factories[name] = factory
            return factory

        return decorator

    def create(self, name: str, options: dict[str, Any] | None = None) -> T:
        try:
            factory = self._factories[name]
        except KeyError:
            raise UnknownComponentError(
                f"unknown {self.kind} {name!r}; available: {', '.join(self.names())}"
            ) from None
        try:
            return factory(**(options or {}))
        except TypeError as exc:
            raise ValueError(f"invalid options for {self.kind} {name!r}: {exc}") from exc

    def names(self) -> list[str]:
        return sorted(self._factories)

    def __contains__(self, name: object) -> bool:
        return name in self._factories
