# loglens

Análise de logs de servidor com detecção de ataques e resumo executivo por IA.

Lê o `access.log` do nginx e o `auth.log` do sshd, aplica seis regras de detecção e devolve um
relatório com o que aconteceu, a gravidade e o que fazer.

[![CI](https://github.com/burnoutscript/loglens/actions/workflows/ci.yml/badge.svg)](https://github.com/burnoutscript/loglens/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependências](https://img.shields.io/badge/dependências-zero-success)
![Licença](https://img.shields.io/badge/licença-MIT-lightgrey)

## Por que fiz isso

Um servidor exposto na internet começa a receber varredura automatizada no primeiro minuto. O
log registra tudo, mas ninguém lê 200 mil linhas por dia, e um SIEM completo custa caro e pede
infraestrutura própria. O loglens fica no meio: um comando, um arquivo de log, um relatório
que dá para ler.

## Instalação

```bash
git clone https://github.com/burnoutscript/loglens.git
cd loglens
pip install -e .
```

Python 3.10+. A análise roda inteira sobre a biblioteca padrão, sem dependência externa.

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

Exemplo de saída:

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

Para reproduzir com os logs de exemplo do repositório:

```bash
loglens samples/auth.log
loglens samples/nginx_access.log
```

## Regras de detecção

| ID | Regra | Severidade | O que procura |
|---|---|---|---|
| LL001 | Força bruta | Alta | Falhas de autenticação do mesmo IP concentradas em uma janela |
| LL002 | Login após falhas | Crítica | Autenticação aceita logo depois de uma rajada de falhas |
| LL003 | Caminho sensível | Alta / Crítica | Requisições a `.env`, `.git`, `/admin`; crítica se o servidor respondeu 2xx |
| LL004 | Ferramenta de varredura | Média | User-Agent de sqlmap, nikto, gobuster e similares |
| LL005 | Enumeração | Média | Volume de 404 para caminhos distintos |
| LL006 | Volume elevado | Baixa | IP muito acima da média de requisições |

### Por que a força bruta usa janela deslizante

Contar o total de falhas por IP gera falso positivo. Cinquenta falhas espalhadas por uma semana
é alguém esquecendo a senha; seis falhas em dois minutos é ataque. Por isso a LL001 só conta as
falhas dentro de um intervalo configurável (`--window`, padrão de 10 minutos).

### A LL002

Força bruta bloqueada acontece todo dia e quase sempre é ruído. Força bruta que termina em login
aceito quer dizer que alguém entrou no servidor. A LL002 separa um caso do outro, e foi por causa
dela que eu escrevi a ferramenta: é a diferença entre reagir no mesmo dia e descobrir semanas
depois.

## A parte de IA

Com `--ai`, os achados viram um resumo executivo em linguagem simples. Três decisões por trás
disso.

O log cru nunca sai da máquina. Só vão os achados já normalizados, com os IPs mascarados
(`203.0.113.47` vira `203.0.113.x`). Log de produção carrega token de sessão, e-mail de usuário
e caminho interno, e mandar isso para a API de um terceiro seria um vazamento.

Não uso SDK. A chamada é feita com `urllib` da biblioteca padrão, o que mantém o projeto sem
dependências e deixa a troca de provedor a uma variável de ambiente de distância:
`LOGLENS_BASE_URL` aceita qualquer endpoint compatível com a API da OpenAI, inclusive modelos
locais via Ollama ou LM Studio.

Se a IA falhar (sem chave, sem internet, API fora do ar), a ferramenta avisa e entrega o
relatório completo do mesmo jeito. Quem encontra os problemas são as regras determinísticas; a
IA só explica o que elas acharam, então a análise não pode depender de a API responder.

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

Parser e regra não se conhecem. Toda regra opera sobre `LogEvent`, nunca sobre o texto bruto.
Na prática, suportar um formato novo (Apache, Caddy, CloudFront) é escrever um parser, e as seis
regras passam a funcionar nele. Escrever uma regra nova também não exige mexer em parser
nenhum.

### Código de saída

| Código | Significado |
|---|---|
| `0` | Nenhum achado |
| `1` | Achados encontrados |
| `2` | Erro (arquivo ausente, formato irreconhecível) |

Isso permite usar em cron ou CI: `loglens /var/log/auth.log || notificar-equipe`.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest -v        # 43 testes
ruff check src tests
```

Os testes cobrem cada regra nos dois sentidos: o caso que deve disparar e o caso parecido que
não deve. Em ferramenta de segurança, falso positivo custa mais que falso negativo, porque a
equipe aprende a ignorar alerta que dispara sem motivo.

## Limitações conhecidas

- Trabalha sobre arquivo, não sobre fluxo contínuo. Para monitorar em tempo real, agende via cron.
- O `auth.log` não registra o ano, então o parser assume o ano corrente (dá para ajustar no construtor).
- Não há correlação entre IPs: um ataque distribuído em muitos endereços passa pelas regras que olham uma origem só.
- As regras usam limiar, não aprendizado de máquina. Fiz assim de propósito: numa investigação, poder auditar e explicar cada alerta vale mais que um ganho pequeno de precisão.

## Licença

MIT. Veja [LICENSE](LICENSE).
