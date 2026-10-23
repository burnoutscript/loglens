"""Regras de detecção.

Cada detector recebe a lista completa de eventos e devolve achados (`Finding`).
Separar regra de parser significa que uma regra nova funciona para todo formato
de log já suportado, sem alteração nos parsers.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from .events import EventKind, Finding, LogEvent, Severity

# Caminhos que nenhum usuário legítimo pede, mas que todo scanner automatizado tenta.
SENSITIVE_PATHS = (
    "/.env",
    "/.git",
    "/.aws",
    "/config.json",
    "/wp-login.php",
    "/wp-admin",
    "/phpmyadmin",
    "/admin",
    "/.ssh",
    "/backup",
    "/.DS_Store",
    "/server-status",
    "/actuator",
    "/vendor/phpunit",
)

# Assinaturas de ferramentas de varredura no User-Agent.
SCANNER_AGENTS = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "dirbuster",
    "gobuster",
    "wpscan",
    "havij",
    "acunetix",
    "nessus",
)


@dataclass
class DetectorConfig:
    """Limiares das regras. Expostos para poder calibrar por ambiente."""

    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 10
    not_found_threshold: int = 15
    high_volume_threshold: int = 300
    sensitive_path_threshold: int = 1


class Detector(Protocol):
    rule_id: str

    def run(self, events: Sequence[LogEvent], config: DetectorConfig) -> list[Finding]: ...


def _group_by_ip(events: Sequence[LogEvent]) -> dict[str, list[LogEvent]]:
    grouped: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        grouped[event.source_ip].append(event)
    return grouped


def _window(events: Sequence[LogEvent]) -> tuple:
    ordered = sorted(events, key=lambda e: e.timestamp)
    return ordered[0].timestamp, ordered[-1].timestamp


class BruteForceDetector:
    """Muitas falhas de autenticação do mesmo IP em uma janela curta.

    Usa janela deslizante em vez de contagem total: 50 falhas espalhadas em uma
    semana é usuário esquecendo a senha; 6 falhas em 2 minutos é ataque.
    """

    rule_id = "LL001"

    def run(self, events: Sequence[LogEvent], config: DetectorConfig) -> list[Finding]:
        findings: list[Finding] = []
        window = timedelta(minutes=config.brute_force_window_minutes)

        for ip, ip_events in _group_by_ip(events).items():
            failures = sorted(
                (e for e in ip_events if e.kind == EventKind.AUTH_FAILURE),
                key=lambda e: e.timestamp,
            )
            if len(failures) < config.brute_force_threshold:
                continue

            burst: list[LogEvent] = []
            start = 0
            for end in range(len(failures)):
                while failures[end].timestamp - failures[start].timestamp > window:
                    start += 1
                if end - start + 1 >= config.brute_force_threshold:
                    burst = failures[start : end + 1]

            if not burst:
                continue

            users = sorted({e.username for e in burst if e.username})
            first, last = _window(burst)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Força bruta em autenticação",
                    severity=Severity.HIGH,
                    source_ip=ip,
                    event_count=len(burst),
                    first_seen=first,
                    last_seen=last,
                    description=(
                        f"{len(burst)} falhas de autenticação em "
                        f"{config.brute_force_window_minutes} minutos, testando "
                        f"{len(users)} usuário(s): {', '.join(users[:5]) or 'não identificado'}."
                    ),
                    recommendation=(
                        "Bloquear o IP no firewall, confirmar que o fail2ban está ativo para o "
                        "serviço e desabilitar autenticação por senha em favor de chave SSH."
                    ),
                    evidence=[e.raw for e in burst[:5]],
                )
            )
        return findings


class CredentialStuffingDetector:
    """Autenticação bem-sucedida logo depois de uma sequência de falhas.

    É o achado mais grave do conjunto: indica que o ataque de força bruta pode
    ter funcionado e que a conta já está comprometida.
    """

    rule_id = "LL002"

    def run(self, events: Sequence[LogEvent], config: DetectorConfig) -> list[Finding]:
        findings: list[Finding] = []

        for ip, ip_events in _group_by_ip(events).items():
            attempts = sorted(
                (e for e in ip_events if e.is_auth_attempt), key=lambda e: e.timestamp
            )
            failures_before = 0
            for event in attempts:
                if event.kind == EventKind.AUTH_FAILURE:
                    failures_before += 1
                    continue

                if failures_before >= config.brute_force_threshold:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title="Login aceito após sequência de falhas",
                            severity=Severity.CRITICAL,
                            source_ip=ip,
                            event_count=failures_before + 1,
                            first_seen=attempts[0].timestamp,
                            last_seen=event.timestamp,
                            description=(
                                f"O usuário '{event.username or 'desconhecido'}' autenticou com "
                                f"sucesso após {failures_before} falhas do mesmo IP. Indício de "
                                "credencial adivinhada ou vazada."
                            ),
                            recommendation=(
                                "Tratar a conta como comprometida: encerrar as sessões, trocar a "
                                "credencial, revisar o que foi acessado depois desse horário e "
                                "verificar persistência (chaves autorizadas, cron, novos usuários)."
                            ),
                            evidence=[event.raw],
                        )
                    )
                failures_before = 0
        return findings


class SensitivePathDetector:
    """Requisições a arquivos de configuração e painéis administrativos."""

    rule_id = "LL003"

    def run(self, events: Sequence[LogEvent], config: DetectorConfig) -> list[Finding]:
        findings: list[Finding] = []

        for ip, ip_events in _group_by_ip(events).items():
            hits = [
                e
                for e in ip_events
                if e.path and any(e.path.lower().startswith(p) for p in SENSITIVE_PATHS)
            ]
            if len(hits) < config.sensitive_path_threshold:
                continue

            leaked = [e for e in hits if e.status and 200 <= e.status < 300]
            leaked_paths = ", ".join(sorted({e.path for e in leaked if e.path}))
            paths = sorted({e.path for e in hits if e.path})
            first, last = _window(hits)

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=(
                        "Arquivo sensível exposto"
                        if leaked
                        else "Varredura por arquivos sensíveis"
                    ),
                    severity=Severity.CRITICAL if leaked else Severity.HIGH,
                    source_ip=ip,
                    event_count=len(hits),
                    first_seen=first,
                    last_seen=last,
                    description=(
                        (
                            f"O servidor respondeu com sucesso a {len(leaked)} requisição(ões) "
                            f"para caminho sensível: {leaked_paths}. "
                            "O conteúdo foi entregue ao solicitante."
                        )
                        if leaked
                        else (
                            f"{len(hits)} tentativa(s) de acesso a {len(paths)} caminho(s) "
                            f"sensível(is): {', '.join(paths[:6])}."
                        )
                    ),
                    recommendation=(
                        "Garantir que o servidor web negue dotfiles e diretórios de configuração, "
                        "mover segredos para variáveis de ambiente e rotacionar qualquer "
                        "credencial que possa ter sido servida."
                    ),
                    evidence=[e.raw for e in (leaked or hits)[:5]],
                )
            )
        return findings


class ScannerAgentDetector:
    """User-Agent declarando ferramenta de varredura."""

    rule_id = "LL004"

    def run(self, events: Sequence[LogEvent], config: DetectorConfig) -> list[Finding]:
        findings: list[Finding] = []

        for ip, ip_events in _group_by_ip(events).items():
            hits = [
                e
                for e in ip_events
                if e.user_agent and any(a in e.user_agent.lower() for a in SCANNER_AGENTS)
            ]
            if not hits:
                continue

            tools = sorted(
                {
                    agent
                    for e in hits
                    if e.user_agent
                    for agent in SCANNER_AGENTS
                    if agent in e.user_agent.lower()
                }
            )
            first, last = _window(hits)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Ferramenta de varredura identificada",
                    severity=Severity.MEDIUM,
                    source_ip=ip,
                    event_count=len(hits),
                    first_seen=first,
                    last_seen=last,
                    description=(
                        f"{len(hits)} requisição(ões) com User-Agent de ferramenta de varredura "
                        f"({', '.join(tools)}). Atacante com alguma competência troca o "
                        "User-Agent, então isto é ruído automatizado ou teste descuidado."
                    ),
                    recommendation=(
                        "Bloquear no WAF por assinatura de User-Agent e revisar se alguma das "
                        "requisições retornou 2xx."
                    ),
                    evidence=[e.raw for e in hits[:5]],
                )
            )
        return findings


class EnumerationDetector:
    """Volume anormal de 404: alguém mapeando o que existe no servidor."""

    rule_id = "LL005"

    def run(self, events: Sequence[LogEvent], config: DetectorConfig) -> list[Finding]:
        findings: list[Finding] = []

        for ip, ip_events in _group_by_ip(events).items():
            not_found = [e for e in ip_events if e.status == 404]
            if len(not_found) < config.not_found_threshold:
                continue

            unique_paths = {e.path for e in not_found}
            first, last = _window(not_found)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Enumeração de diretórios",
                    severity=Severity.MEDIUM,
                    source_ip=ip,
                    event_count=len(not_found),
                    first_seen=first,
                    last_seen=last,
                    description=(
                        f"{len(not_found)} respostas 404 para {len(unique_paths)} caminhos "
                        "distintos, padrão típico de varredura por lista de palavras."
                    ),
                    recommendation=(
                        "Aplicar rate limiting por IP e revisar se algum dos caminhos testados "
                        "existe de fato e está sem autenticação."
                    ),
                    evidence=[e.raw for e in not_found[:5]],
                )
            )
        return findings


class HighVolumeDetector:
    """IP com volume de requisições muito acima do restante."""

    rule_id = "LL006"

    def run(self, events: Sequence[LogEvent], config: DetectorConfig) -> list[Finding]:
        findings: list[Finding] = []

        for ip, ip_events in _group_by_ip(events).items():
            if len(ip_events) < config.high_volume_threshold:
                continue
            first, last = _window(ip_events)
            minutes = max((last - first).total_seconds() / 60, 1)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title="Volume de requisições elevado",
                    severity=Severity.LOW,
                    source_ip=ip,
                    event_count=len(ip_events),
                    first_seen=first,
                    last_seen=last,
                    description=(
                        f"{len(ip_events)} requisições em {minutes:.0f} minutos "
                        f"({len(ip_events) / minutes:.1f} por minuto). Pode ser bot legítimo, "
                        "proxy corporativo ou abuso."
                    ),
                    recommendation=(
                        "Checar o ASN de origem antes de bloquear: pode ser crawler de buscador "
                        "ou saída NAT de uma rede inteira."
                    ),
                    evidence=[e.raw for e in ip_events[:3]],
                )
            )
        return findings


ALL_DETECTORS: list[Detector] = [
    BruteForceDetector(),
    CredentialStuffingDetector(),
    SensitivePathDetector(),
    ScannerAgentDetector(),
    EnumerationDetector(),
    HighVolumeDetector(),
]


def analyze(
    events: Sequence[LogEvent],
    config: DetectorConfig | None = None,
    detectors: Sequence[Detector] | None = None,
) -> list[Finding]:
    """Roda todos os detectores e devolve os achados do mais grave para o menos."""
    config = config or DetectorConfig()
    findings: list[Finding] = []
    for detector in detectors or ALL_DETECTORS:
        findings.extend(detector.run(events, config))

    findings.sort(key=lambda f: (-f.severity.rank, -f.event_count))
    return findings
