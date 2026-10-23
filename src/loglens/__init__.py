"""loglens — análise de logs de servidor com detecção de ataques e resumo por IA."""

__version__ = "0.1.0"

from .detectors import DetectorConfig, analyze
from .events import EventKind, Finding, LogEvent, Severity
from .parsers import parse_lines

__all__ = [
    "analyze",
    "DetectorConfig",
    "EventKind",
    "Finding",
    "LogEvent",
    "Severity",
    "parse_lines",
    "__version__",
]
