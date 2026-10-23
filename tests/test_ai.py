import json

import pytest

from loglens.ai import AIUnavailable, build_prompt, mask_ip, summarize_findings
from tests.test_report import FINDING


def test_mascara_ultimo_octeto():
    assert mask_ip("203.0.113.47") == "203.0.113.x"


def test_mascara_preserva_entrada_estranha():
    assert mask_ip("invalido") == "invalido"


def test_prompt_nao_contem_ip_completo():
    prompt = build_prompt([FINDING])
    assert "203.0.113.47" not in prompt
    assert "203.0.113.x" in prompt


def test_prompt_e_json_valido():
    assert json.loads(build_prompt([FINDING]))[0]["regra"] == "LL001"


def test_sem_chave_levanta_ai_unavailable(monkeypatch):
    monkeypatch.delenv("LOGLENS_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(AIUnavailable):
        summarize_findings([FINDING])


def test_sem_achados_levanta_ai_unavailable():
    with pytest.raises(AIUnavailable):
        summarize_findings([])
