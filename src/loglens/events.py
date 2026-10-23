"""Modelo de evento normalizado.

Cada parser converte o formato bruto do seu log para `LogEvent`, de modo que os
detectores funcionem sem saber de onde o dado veio.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EventKind(str, Enum):
    """O que aconteceu, independente da origem do log."""

    HTTP_REQUEST = "http_request"
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LogEvent:
    """Uma linha de log já normalizada."""

    timestamp: datetime
    source_ip: str
    kind: EventKind
    raw: str
    path: str | None = None
    method: str | None = None
    status: int | None = None
    user_agent: str | None = None
    username: str | None = None
    service: str | None = None

    @property
    def is_auth_attempt(self) -> bool:
        return self.kind in (EventKind.AUTH_FAILURE, EventKind.AUTH_SUCCESS)


class Severity(str, Enum):
    """Severidade de um achado, do menos para o mais grave."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self)


@dataclass
class Finding:
    """Algo suspeito que um detector encontrou."""

    rule_id: str
    title: str
    severity: Severity
    source_ip: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    recommendation: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "event_count": self.event_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence[:5],
        }
