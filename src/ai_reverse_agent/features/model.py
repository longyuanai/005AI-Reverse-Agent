"""Parser-independent feature index with four explicit scopes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class FeatureScope(str, Enum):
    FILE = "file"
    FUNCTION = "function"
    BASIC_BLOCK = "basic-block"
    INSTRUCTION = "instruction"


@dataclass(frozen=True)
class ScopedFeature:
    scope: FeatureScope
    key: str
    value: Any
    address: int | None = None


@dataclass(frozen=True)
class FeatureIndex:
    """Immutable feature collection shared by every rule in one scan."""

    file: Mapping[str, Any]
    functions: tuple[Mapping[str, Any], ...] = ()
    basic_blocks: tuple[Mapping[str, Any], ...] = ()
    instructions: tuple[Any, ...] = ()
    _flat: tuple[ScopedFeature, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", MappingProxyType(dict(self.file)))
        object.__setattr__(
            self,
            "functions",
            tuple(MappingProxyType(dict(item)) for item in self.functions),
        )
        object.__setattr__(
            self,
            "basic_blocks",
            tuple(MappingProxyType(dict(item)) for item in self.basic_blocks),
        )

    def find(self, scope: FeatureScope, key: str) -> tuple[ScopedFeature, ...]:
        return tuple(
            item for item in self._flat if item.scope is scope and item.key == key
        )

    def rule_facts(self) -> Mapping[str, Any]:
        """Compatibility facts for frozen RuleContext consumers."""
        return MappingProxyType(
            {
                "feature_index": self,
                "data": self.file.get("data", b""),
                "imports": self.file.get("imports", ()),
                "backend": self.file.get("backend", "unknown"),
                "architecture": self.file.get("architecture"),
                "cfg": self.file.get("cfg"),
                "cfg_metrics": self.file.get("cfg_metrics", {}),
                "instructions": self.instructions,
            }
        )
