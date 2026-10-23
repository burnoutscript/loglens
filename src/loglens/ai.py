"""Camada opcional de IA: transforma achados técnicos em resumo executivo.

Escolhas de projeto que valem explicação:

* **Sem SDK.** A chamada é feita com `urllib`, da biblioteca padrão. O projeto
  inteiro roda com zero dependências, e trocar de provedor é mudar uma URL.
* **Nada de log cru no prompt.** Só os achados já normalizados são enviados, e
  mesmo assim com os IPs mascarados. Log de produção contém token de sessão,
  e-mail e caminho interno; mandar isso para uma API de terceiro é vazamento.
* **Degrada em silêncio.** Sem chave de API, a ferramenta continua funcionando
  normalmente e só omite o resumo. A IA é um acréscimo, não o produto.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Sequence

from .events import Finding

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
TIMEOUT_SECONDS = 30

SYSTEM_PROMPT = (
    "Você é um analista de segurança. Recebe achados automatizados de uma análise de "
    "logs e escreve um resumo executivo em português do Brasil, com no máximo três "
    "parágrafos. Comece pelo risco mais grave, explique o impacto prático em "
    "linguagem que um gestor não técnico entenda e termine com a ação mais urgente. "
    "Não invente dados que não estejam nos achados. Se os achados forem ruído "
    "automatizado comum na internet, diga isso em vez de criar alarme."
)


def mask_ip(ip: str) -> str:
    """Mascara o último octeto: 203.0.113.47 vira 203.0.113.x.

    Preserva a rede de origem, que é o que importa para a análise, sem enviar o
    endereço completo para fora.
    """
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["x"])
    return ip.rsplit(":", 1)[0] + ":x" if ":" in ip else ip


class AIUnavailable(RuntimeError):
    """Resumo por IA não pôde ser gerado. Não interrompe a análise."""


def build_prompt(findings: Sequence[Finding]) -> str:
    """Monta o conteúdo enviado ao modelo, já sanitizado."""
    payload = [
        {
            "severidade": f.severity.value,
            "regra": f.rule_id,
            "titulo": f.title,
            "origem": mask_ip(f.source_ip),
            "eventos": f.event_count,
            "descricao": f.description,
        }
        for f in findings
    ]
    return json.dumps(payload, ensure_ascii=False, indent=2)


def summarize_findings(
    findings: Sequence[Finding],
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> str:
    """Pede ao modelo um resumo executivo dos achados.

    Levanta `AIUnavailable` se não houver chave ou se a API falhar — cabe ao
    chamador seguir sem o resumo.
    """
    if not findings:
        raise AIUnavailable("Não há achados para resumir.")

    api_key = api_key or os.environ.get("LOGLENS_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise AIUnavailable(
            "Nenhuma chave de API encontrada. Defina LOGLENS_API_KEY para habilitar o resumo."
        )

    base_url = (base_url or os.environ.get("LOGLENS_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
    model = model or os.environ.get("LOGLENS_MODEL") or DEFAULT_MODEL

    body = json.dumps(
        {
            "model": model,
            "temperature": 0.2,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_prompt(findings)},
            ],
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise AIUnavailable(f"A API respondeu {exc.code}. Resumo não gerado.") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise AIUnavailable(f"Falha de rede ao chamar a API: {exc}.") from exc
    except json.JSONDecodeError as exc:
        raise AIUnavailable("A API devolveu uma resposta ilegível.") from exc

    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError) as exc:
        raise AIUnavailable("A resposta da API veio em formato inesperado.") from exc
