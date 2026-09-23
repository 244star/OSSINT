from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import time


class IdentifierType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    NAME = "name"
    DOMAIN = "domain"


class Confidence(str, Enum):
    VERIFIED = "verified"   # target server explicitly confirmed existence
    LIKELY = "likely"       # >=2 independent sources corroborate
    UNSURE = "unsure"       # single weak source / collision risk


@dataclass(frozen=True)
class Identifier:
    type: IdentifierType
    value: str

    def key(self) -> str:
        return f"{self.type.value}:{self.value.strip().lower()}"

    def __str__(self) -> str:
        return f"{self.type.value}:{self.value}"

    def to_dict(self) -> dict:
        return {"type": self.type.value, "value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Identifier":
        return cls(IdentifierType(data["type"]), data["value"])


@dataclass
class Finding:
    source: str
    identifier: Identifier
    confidence: Confidence
    url: str | None = None
    details: dict = field(default_factory=dict)
    pivots: list = field(default_factory=list)
    discovered: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        """Plain-dict form suitable for JSON caching / serialization."""
        return {
            "source": self.source,
            "identifier": self.identifier.to_dict(),
            "confidence": self.confidence.value,
            "url": self.url,
            "details": self.details,
            "pivots": [p.to_dict() for p in self.pivots],
            "discovered": self.discovered,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(
            source=data["source"],
            identifier=Identifier.from_dict(data["identifier"]),
            confidence=Confidence(data["confidence"]),
            url=data.get("url"),
            details=data.get("details", {}),
            pivots=[Identifier.from_dict(p) for p in data.get("pivots", [])],
            discovered=data.get("discovered", time.time()),
        )
