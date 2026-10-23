"""Interface de linha de comando do loglens."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .ai import AIUnavailable, summarize_findings
from .detectors import ALL_DETECTORS, DetectorConfig, analyze
from .parsers import PARSERS, parse_lines
from .report import to_json, to_markdown, to_terminal

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loglens",
        description="Analisa logs de servidor em busca de indícios de ataque.",
        epilog="Exemplo: loglens samples/nginx_access.log --format markdown -o relatorio.md",
    )
    parser.add_argument("logfile", type=Path, help="arquivo de log a analisar ('-' para stdin)")
    parser.add_argument(
        "--format",
        choices=("terminal", "json", "markdown"),
        default="terminal",
        help="formato da saída (padrão: terminal)",
    )
    parser.add_argument("-o", "--output", type=Path, help="grava o relatório em arquivo")
    parser.add_argument(
        "--parser",
        choices=[p.name for p in PARSERS],
        help="força um parser em vez de detectar o formato automaticamente",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="gera resumo executivo com IA (requer LOGLENS_API_KEY)",
    )
    parser.add_argument(
        "--min-severity",
        choices=("info", "low", "medium", "high", "critical"),
        default="info",
        help="esconde achados abaixo desta severidade",
    )
    parser.add_argument(
        "--brute-force-threshold",
        type=int,
        default=5,
        help="falhas de autenticação na janela para considerar força bruta (padrão: 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="tamanho da janela de análise em minutos (padrão: 10)",
    )
    parser.add_argument("--no-color", action="store_true", help="desliga cores no terminal")
    parser.add_argument("--version", action="version", version=f"loglens {__version__}")
    return parser


def read_lines(path: Path) -> list[str]:
    if str(path) == "-":
        return sys.stdin.read().splitlines()
    if not path.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {path}")
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        lines = read_lines(args.logfile)
    except (FileNotFoundError, PermissionError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return EXIT_ERROR

    chosen = next((p for p in PARSERS if p.name == args.parser), None) if args.parser else None
    events = list(parse_lines(lines, chosen))

    if not events:
        print(
            "erro: nenhuma linha reconhecida. Use --parser para indicar o formato.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    config = DetectorConfig(
        brute_force_threshold=args.brute_force_threshold,
        brute_force_window_minutes=args.window,
    )
    findings = analyze(events, config, ALL_DETECTORS)

    order = ["info", "low", "medium", "high", "critical"]
    floor = order.index(args.min_severity)
    findings = [f for f in findings if order.index(f.severity.value) >= floor]

    ai_summary = None
    if args.ai:
        try:
            ai_summary = summarize_findings(findings)
        except AIUnavailable as exc:
            print(f"aviso: {exc}", file=sys.stderr)

    if args.format == "json":
        output = to_json(events, findings)
    elif args.format == "markdown":
        output = to_markdown(events, findings, ai_summary)
    else:
        output = to_terminal(events, findings, color=not args.no_color)
        if ai_summary:
            output += f"\n  Resumo:\n\n  {ai_summary}\n"

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Relatório gravado em {args.output}")
    else:
        print(output)

    # Código de saída diferente de zero quando há achado: permite usar em CI
    # e em cron com alerta automático.
    return EXIT_FINDINGS if findings else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
