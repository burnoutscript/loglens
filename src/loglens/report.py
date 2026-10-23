"""Formatação dos achados: terminal, JSON e Markdown."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence

from .events import Finding, LogEvent, Severity

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    Severity.CRITICAL: "\033[97;41m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
LABELS = {
    Severity.CRITICAL: "CRÍTICO",
    Severity.HIGH: "ALTO",
    Severity.MEDIUM: "MÉDIO",
    Severity.LOW: "BAIXO",
    Severity.INFO: "INFO",
}


def summarize(events: Sequence[LogEvent], findings: Sequence[Finding]) -> dict:
    """Estatísticas gerais da varredura."""
    by_severity = Counter(f.severity.value for f in findings)
    return {
        "events_analyzed": len(events),
        "unique_ips": len({e.source_ip for e in events}),
        "findings": len(findings),
        "by_severity": dict(by_severity),
        "period": {
            "start": min((e.timestamp for e in events), default=None),
            "end": max((e.timestamp for e in events), default=None),
        },
    }


def to_terminal(events: Sequence[LogEvent], findings: Sequence[Finding], color: bool = True) -> str:
    """Relatório colorido para leitura direta no terminal."""

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    stats = summarize(events, findings)
    lines = [
        "",
        paint("  loglens — relatório de análise", BOLD),
        f"  {stats['events_analyzed']} eventos · {stats['unique_ips']} IPs distintos · "
        f"{stats['findings']} achado(s)",
        "  " + "─" * 66,
    ]

    if not findings:
        lines += ["", "  Nenhum padrão suspeito encontrado nas regras ativas.", ""]
        return "\n".join(lines)

    for finding in findings:
        badge = paint(f" {LABELS[finding.severity]} ", COLORS[finding.severity])
        lines += [
            "",
            f"  {badge} {paint(finding.title, BOLD)}  {paint(finding.rule_id, DIM)}",
            f"  Origem: {finding.source_ip}   Eventos: {finding.event_count}",
            f"  Janela: {finding.first_seen:%d/%m %H:%M} → {finding.last_seen:%d/%m %H:%M}",
            "",
            f"  {finding.description}",
            "",
            paint(f"  → {finding.recommendation}", DIM),
        ]
        if finding.evidence:
            lines.append(paint(f"  evidência: {finding.evidence[0][:100]}", DIM))

    lines.append("")
    return "\n".join(lines)


def to_json(events: Sequence[LogEvent], findings: Sequence[Finding]) -> str:
    """Saída legível por máquina, para integrar com SIEM ou pipeline."""
    stats = summarize(events, findings)
    period = stats["period"]
    stats["period"] = {
        "start": period["start"].isoformat() if period["start"] else None,
        "end": period["end"].isoformat() if period["end"] else None,
    }
    return json.dumps(
        {"summary": stats, "findings": [f.to_dict() for f in findings]},
        indent=2,
        ensure_ascii=False,
    )


def to_markdown(
    events: Sequence[LogEvent], findings: Sequence[Finding], ai_summary: str | None = None
) -> str:
    """Relatório para anexar em chamado, issue ou e-mail."""
    stats = summarize(events, findings)
    period = stats["period"]

    lines = [
        "# Relatório de análise de logs",
        "",
        f"- **Eventos analisados:** {stats['events_analyzed']}",
        f"- **IPs distintos:** {stats['unique_ips']}",
        f"- **Achados:** {stats['findings']}",
    ]
    if period["start"] and period["end"]:
        lines.append(
            f"- **Período:** {period['start']:%d/%m/%Y %H:%M} a {period['end']:%d/%m/%Y %H:%M}"
        )

    if ai_summary:
        lines += ["", "## Resumo executivo", "", ai_summary]

    if not findings:
        lines += ["", "Nenhum padrão suspeito encontrado nas regras ativas."]
        return "\n".join(lines)

    lines += [
        "",
        "## Achados",
        "",
        "| Severidade | Regra | Título | Origem | Eventos |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(
            f"| {LABELS[f.severity]} | {f.rule_id} | {f.title} "
            f"| `{f.source_ip}` | {f.event_count} |"
        )

    lines += ["", "## Detalhamento", ""]
    for f in findings:
        lines += [
            f"### {LABELS[f.severity]} · {f.title} (`{f.rule_id}`)",
            "",
            f"**Origem:** `{f.source_ip}` · "
            f"**Janela:** {f.first_seen:%d/%m %H:%M} a {f.last_seen:%d/%m %H:%M}",
            "",
            f.description,
            "",
            f"**Ação recomendada:** {f.recommendation}",
            "",
        ]
        if f.evidence:
            lines += ["<details><summary>Evidência</summary>", "", "```"]
            lines += f.evidence[:5]
            lines += ["```", "", "</details>", ""]

    return "\n".join(lines)
