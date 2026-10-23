from datetime import datetime

from loglens.events import EventKind
from loglens.parsers import NginxParser, SshdParser, detect_parser, parse_lines

NGINX_LINE = (
    '203.0.113.47 - - [22/Oct/2026:03:26:00 +0000] "GET /.env HTTP/1.1" 200 412 '
    '"-" "python-requests/2.31.0"'
)
SSHD_FAIL = (
    "Oct 22 02:41:00 prumo-vps sshd[2100]: Failed password for invalid user root "
    "from 203.0.113.47 port 40000 ssh2"
)
SSHD_OK = (
    "Oct 22 02:44:22 prumo-vps sshd[2199]: Accepted password for deploy "
    "from 203.0.113.47 port 40311 ssh2"
)


class TestNginxParser:
    def test_extrai_campos_da_linha(self):
        event = NginxParser().parse(NGINX_LINE)
        assert event is not None
        assert event.source_ip == "203.0.113.47"
        assert event.method == "GET"
        assert event.path == "/.env"
        assert event.status == 200
        assert event.user_agent == "python-requests/2.31.0"
        assert event.kind is EventKind.HTTP_REQUEST

    def test_timestamp_com_fuso(self):
        event = NginxParser().parse(NGINX_LINE)
        assert event.timestamp.year == 2026
        assert event.timestamp.hour == 3
        assert event.timestamp.utcoffset().total_seconds() == 0

    def test_linha_malformada_devolve_none(self):
        assert NginxParser().parse("isto não é um log") is None

    def test_linha_sem_user_agent(self):
        line = '198.51.100.5 - - [22/Oct/2026:03:26:00 +0000] "GET / HTTP/1.1" 200 12'
        event = NginxParser().parse(line)
        assert event is not None
        assert event.user_agent is None


class TestSshdParser:
    def test_falha_de_autenticacao(self):
        event = SshdParser(year=2026).parse(SSHD_FAIL)
        assert event is not None
        assert event.kind is EventKind.AUTH_FAILURE
        assert event.source_ip == "203.0.113.47"
        assert event.username == "root"
        assert event.service == "sshd"

    def test_autenticacao_aceita(self):
        event = SshdParser(year=2026).parse(SSHD_OK)
        assert event is not None
        assert event.kind is EventKind.AUTH_SUCCESS
        assert event.username == "deploy"

    def test_ano_assumido_quando_nao_informado(self):
        event = SshdParser(year=2024).parse(SSHD_FAIL)
        assert event.timestamp == datetime(2024, 10, 22, 2, 41, 0)

    def test_linha_sem_autenticacao_e_ignorada(self):
        line = "Oct 22 02:41:00 prumo-vps CRON[999]: pam_unix(cron:session): session opened"
        assert SshdParser().parse(line) is None


class TestDeteccaoDeFormato:
    def test_identifica_nginx(self):
        assert detect_parser([NGINX_LINE] * 3).name == "nginx"

    def test_identifica_sshd(self):
        assert detect_parser([SSHD_FAIL] * 3).name == "sshd"

    def test_entrada_vazia_devolve_none(self):
        assert detect_parser([]) is None

    def test_formato_desconhecido_devolve_none(self):
        assert detect_parser(["lorem ipsum", "dolor sit amet"]) is None


class TestParseLines:
    def test_pula_linhas_invalidas_sem_quebrar(self):
        events = list(parse_lines([NGINX_LINE, "", "lixo", NGINX_LINE]))
        assert len(events) == 2

    def test_formato_irreconhecivel_nao_rende_eventos(self):
        assert list(parse_lines(["aaa", "bbb"])) == []
