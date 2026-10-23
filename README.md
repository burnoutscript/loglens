# loglens

**Análise de logs de servidor com detecção de ataques e resumo executivo por IA.**

Lê `access.log` do nginx e `auth.log` do sshd, aplica seis regras de detecção e devolve um
relatório que diz o que aconteceu, qual a gravidade e o que fazer a respeito.

[![CI](https://github.com/Kryip/loglens/actions/workflows/ci.yml/badge.svg)](https://github.com/Kryip/loglens/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependências](https://img.shields.io/badge/dependências-zero-success)
![Licença](https://img.shields.io/badge/licença-MIT-lightgrey)

---

## Por que existe

Servidor exposto na internet recebe varredura automatizada desde o primeiro minuto. O log
registra tudo, mas ninguém lê 200 mil linhas por dia. As ferramentas que resolvem isso de
verdade (SIEM completo) custam caro e pedem infraestrutura própria.

O `loglens` ocupa o meio-termo: um comando, um arquivo de log, um relatório legível.

---

## Instalação

```bash
git clone https://github.com/Kryip/loglens.git
cd loglens
pip install -e .
```

Requer Python 3.10 ou superior. **Nenhuma dependência externa** — a análise inteira roda
sobre a biblioteca padrão.

---

## Uso

```bash
# Analisa um log e imprime no terminal
loglens /var/log/nginx/access.log

# Gera relatório em Markdown para anexar em um chamado
loglens /var/log/auth.log --format markdown -o relatorio.md

# Saída JSON, para integrar com outra ferramenta
loglens /var/log/nginx/access.log --format json | jq '.findings[] | select(.severity=="critical")'

# Lê da entrada padrão, útil com journalctl
journalctl -u ssh --no-pager | loglens - --parser sshd

# Mostra só o que for grave
loglens /var/log/nginx/access.log --min-severity high

# Acrescenta resumo executivo gerado por IA
export LOGLENS_API_KEY="sua-chave"
loglens /var/log/auth.log --ai
```

### Exemplo de saída

```
  loglens — relatório de análise
  10 eventos · 2 IPs distintos · 2 achado(s)
  ──────────────────────────────────────────────────────────────────

   CRÍTICO  Login aceito após sequência de falhas  LL002
  Origem: 203.0.113.47   Eventos: 8
  Janela: 22/10 02:41 → 22/10 02:43

  O usuário 'deploy' autenticou com sucesso após 7 falhas do mesmo IP.
  Indício de credencial adivinhada ou vazada.

  → Tratar a conta como comprometida: encerrar as sessões, trocar a credencial,
    revisar o que foi acessado depois desse horário e verificar persistência.

   ALTO  Força bruta em autenticação  LL001
  Origem: 203.0.113.47   Eventos: 7
  Janela: 22/10 02:41 → 22/10 02:43

  7 falhas de autenticação em 10 minutos, testando 7 usuário(s):
  admin, deploy, oracle, postgres, root.
```

Reproduza com os logs de exemplo do repositório:

```bash
loglens samples/auth.log
loglens samples/nginx_access.log
```

---

## Regras de detecção

| ID | Regra | Severidade | O que procura |
|---|---|---|---|
| LL001 | Força bruta | Alta | Falhas de autenticação do mesmo IP concentradas em uma janela |
| LL002 | Login após falhas | **Crítica** | Autenticação aceita logo depois de uma rajada de falhas |
| LL003 | Caminho sensível | Alta / Crítica | Requisições a `.env`, `.git`, `/admin`; crítica se o servidor respondeu 2xx |
| LL004 | Ferramenta de varredura | Média | User-Agent de sqlmap, nikto, gobuster e similares |
| LL005 | Enumeração | Média | Volume de 404 para caminhos distintos |
| LL006 | Volume elevado | Baixa | IP muito acima da média de requisições |

### Janela deslizante, não contagem total

A regra de força bruta é o exemplo de por que o detalhe importa. Contar o total de falhas por
IP gera falso positivo: cinquenta falhas espalhadas por uma semana é alguém esquecendo a
senha. O que caracteriza ataque é a **concentração** — seis falhas em dois minutos.

Por isso a `LL001` usa janela deslizante: a contagem considera apenas as falhas dentro de um
intervalo configurável (`--window`, padrão de 10 minutos).

### A regra que importa de verdade

A `LL002` é a razão da ferramenta existir. Força bruta bloqueada é ruído cotidiano. Força
bruta **bem-sucedida** é incidente: alguém está dentro do servidor. Separar as duas coisas é
a diferença entre reagir hoje e descobrir daqui a três semanas.

---

## A camada de IA

Com `--ai`, os achados viram um resumo executivo em linguagem acessível. Três decisões de
projeto por trás disso:

**O log cru nunca é enviado.** Apenas os achados já normalizados saem da máquina, e com os
IPs mascarados (`203.0.113.47` vira `203.0.113.x`). Log de produção carrega token de sessão,
e-mail de usuário e caminho interno — mandar isso para uma API de terceiro é vazamento com
outro nome.

**Sem SDK.** A chamada usa `urllib` da biblioteca padrão. Mantém o projeto com zero
dependências e deixa a troca de provedor a uma variável de ambiente de distância
(`LOGLENS_BASE_URL` aceita qualquer endpoint compatível com a API da OpenAI, incluindo
modelos locais via Ollama ou LM Studio).

**Degrada em silêncio.** Sem chave, sem internet ou com a API fora do ar, a ferramenta avisa
e segue entregando o relatório completo. A IA explica os achados; quem os encontra são as
regras determinísticas. Produto de segurança que só funciona quando a API responde não é
produto de segurança.

---

## Arquitetura

```
  arquivo de log
        │
        ▼
   ┌─────────┐   detecta o formato automaticamente
   │ parsers │   nginx combined · sshd auth.log
   └────┬────┘
        │  LogEvent  (modelo normalizado)
        ▼
  ┌────────────┐  6 regras independentes
  │ detectores │  recebem eventos, devolvem achados
  └─────┬──────┘
        │  Finding  (severidade, evidência, recomendação)
        ▼
   ┌─────────┐        ┌────────────────┐
   │ report  │◀───────│  ai (opcional) │  resumo executivo
   └────┬────┘        └────────────────┘
        │
   terminal · JSON · Markdown
```

O desenho tem um objetivo: **parser e regra não se conhecem**. Toda regra opera sobre
`LogEvent`, nunca sobre texto bruto. A consequência prática é que suportar um formato novo
(Apache, Caddy, CloudFront) é escrever um parser e nada mais — as seis regras passam a
funcionar nele de graça. E escrever uma regra nova não exige tocar em nenhum parser.

### Código de saída

| Código | Significado |
|---|---|
| `0` | Nenhum achado |
| `1` | Achados encontrados |
| `2` | Erro (arquivo ausente, formato irreconhecível) |

Permite usar em cron ou CI: `loglens /var/log/auth.log || notificar-equipe`.

---

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest -v        # 43 testes
ruff check src tests
```

Os testes cobrem cada regra nos dois sentidos: o caso que **deve** disparar e o caso parecido
que **não deve**. Falso positivo em ferramenta de segurança é pior que falso negativo — alerta
que grita sem motivo é alerta que a equipe aprende a ignorar.

---

## Limitações conhecidas

- Trabalha sobre arquivo, não sobre fluxo contínuo. Para monitoramento em tempo real, agende via cron.
- `auth.log` não registra o ano; o parser assume o ano corrente (ajustável no construtor).
- Correlação entre IPs não é feita: ataque distribuído em muitos endereços passa pelas regras baseadas em origem única.
- As regras são baseadas em limiar, não em aprendizado de máquina. É proposital: limiar é auditável e explicável, e numa investigação isso vale mais que precisão marginal.

## Licença

MIT — veja [LICENSE](LICENSE).
