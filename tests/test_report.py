import json
from datetime import datetime

from loglens.events import Finding, Severity
from loglens.report import summarize, to_json, to_markdown, to_terminal

FINDING = Finding(
    rule_id="LL001",
    title="Força bruta em autenticação",
    severity=Severity.HIGH,
    source_ip="203.0.113.47",
    event_count=7,
    first_seen=datetime(2026, 10, 22, 2, 41),
    last_seen=datetime(2026, 10, 22, 2, 44),
    description="Sete falhas em três minutos.",
    recommendation="Bloquear o IP.",
    evidence=["linha de exemplo"],
)


def test_json_e_valido_e_tem_achados():
    payload = json.loads(to_json([], [FINDING]))
    assert payload["summary"]["findings"] == 1
    assert payload["findings"][0]["rule_id"] == "LL001"


def test_markdown_inclui_titulo_e_recomendacao():
    output = to_markdown([], [FINDING])
    assert "Força bruta em autenticação" in output
    assert "Bloquear o IP." in output


def test_markdown_aceita_resumo_de_ia():
    output = to_markdown([], [FINDING], ai_summary="Resumo gerado.")
    assert "Resumo executivo" in output
    assert "Resumo gerado." in output


def test_terminal_sem_cor_nao_tem_escape_ansi():
    output = to_terminal([], [FINDING], color=False)
    assert "\033[" not in output


def test_sem_achados_informa_log_limpo():
    assert "Nenhum padrão suspeito" in to_terminal([], [], color=False)


def test_summarize_conta_severidades():
    stats = summarize([], [FINDING])
    assert stats["by_severity"]["high"] == 1
