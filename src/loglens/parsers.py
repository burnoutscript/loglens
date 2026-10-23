"""Parsers de formatos de log para o modelo normalizado `LogEvent`."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import Protocol

from .events import EventKind, LogEvent

# ---------------------------------------------------------------------------
# nginx / apache — formato "combined"
# 1.2.3.4 - - [23/Oct/2026:13:05:11 +0000] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.1"
# ---------------------------------------------------------------------------
_NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S*)\s*(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)
_NGINX_TIME = "%d/%b/%Y:%H:%M:%S %z"

# ---------------------------------------------------------------------------
# sshd / auth.log
# Oct 23 13:05:11 host sshd[1234]: Failed password for invalid user
#   admin from 1.2.3.4 port 52344 ssh2
# ---------------------------------------------------------------------------
_SSHD_RE = re.compile(
    r'^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>\w+)(?:\[\d+\])?:\s+(?P<message>.*)$'
)
_SSHD_FAIL = re.compile(
    r'(?:Failed|Invalid)\s+(?:password|user)\s+(?:for\s+)?(?:invalid user\s+)?'
    r'(?P<user>\S+)?\s*(?:from\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+)'
)
_SSHD_OK = re.compile(
    r'Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)
_SSHD_TIME = "%Y %b %d %H:%M:%S"


class Parser(Protocol):
    """Contrato que todo parser cumpre."""

    name: str

    def matches(self, line: str) -> bool: ...

    def parse(self, line: str) -> LogEvent | None: ...


class NginxParser:
    """Lê o formato combined do nginx e do Apache."""

    name = "nginx"

    def matches(self, line: str) -> bool:
        return _NGINX_RE.match(line) is not None

    def parse(self, line: str) -> LogEvent | None:
        match = _NGINX_RE.match(line)
        if not match:
            return None
        try:
            timestamp = datetime.strptime(match.group("time"), _NGINX_TIME)
        except ValueError:
            return None
        return LogEvent(
            timestamp=timestamp,
            source_ip=match.group("ip"),
            kind=EventKind.HTTP_REQUEST,
            raw=line.rstrip("\n"),
            path=match.group("path"),
            method=match.group("method"),
            status=int(match.group("status")),
            user_agent=match.group("agent") or None,
            service="http",
        )


class SshdParser:
    """Lê linhas de autenticação do sshd em /var/log/auth.log."""

    name = "sshd"

    def __init__(self, year: int | None = None) -> None:
        # auth.log não registra o ano; assume o ano corrente salvo indicação contrária.
        self.year = year or datetime.now().year

    def matches(self, line: str) -> bool:
        return _SSHD_RE.match(line) is not None

    def parse(self, line: str) -> LogEvent | None:
        match = _SSHD_RE.match(line)
        if not match:
            return None
        message = match.group("message")

        success = _SSHD_OK.search(message)
        failure = None if success else _SSHD_FAIL.search(message)
        hit = success or failure
        if not hit:
            return None

        try:
            # O ano entra na própria string: `strptime` sem ano é depreciado e
            # quebra em 29 de fevereiro.
            timestamp = datetime.strptime(f"{self.year} {match.group('time')}", _SSHD_TIME)
        except ValueError:
            return None

        return LogEvent(
            timestamp=timestamp,
            source_ip=hit.group("ip"),
            kind=EventKind.AUTH_SUCCESS if success else EventKind.AUTH_FAILURE,
            raw=line.rstrip("\n"),
            username=hit.groupdict().get("user"),
            service=match.group("service"),
        )


PARSERS: list[Parser] = [NginxParser(), SshdParser()]


def detect_parser(lines: Iterable[str], sample_size: int = 20) -> Parser | None:
    """Descobre o formato do log olhando as primeiras linhas.

    Vence o parser que casar com mais linhas da amostra. Empate ou nenhum
    acerto devolve None, e o chamador decide o que fazer.
    """
    sample = [line for line in list(lines)[:sample_size] if line.strip()]
    if not sample:
        return None

    scores = {parser.name: sum(parser.matches(line) for line in sample) for parser in PARSERS}
    best = max(PARSERS, key=lambda p: scores[p.name])
    return best if scores[best.name] > 0 else None


def parse_lines(lines: Iterable[str], parser: Parser | None = None) -> Iterator[LogEvent]:
    """Converte linhas de log em eventos, pulando o que não for reconhecido."""
    lines = list(lines)
    chosen = parser or detect_parser(lines)
    if chosen is None:
        return

    for line in lines:
        if not line.strip():
            continue
        event = chosen.parse(line)
        if event is not None:
            yield event
