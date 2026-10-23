from datetime import datetime, timedelta

from loglens.detectors import (
    BruteForceDetector,
    CredentialStuffingDetector,
    DetectorConfig,
    EnumerationDetector,
    ScannerAgentDetector,
    SensitivePathDetector,
    analyze,
)
from loglens.events import EventKind, LogEvent, Severity

BASE = datetime(2026, 10, 22, 2, 0, 0)
CONFIG = DetectorConfig()


def auth_event(seconds: int, ip: str = "203.0.113.47", ok: bool = False, user: str = "root"):
    return LogEvent(
        timestamp=BASE + timedelta(seconds=seconds),
        source_ip=ip,
        kind=EventKind.AUTH_SUCCESS if ok else EventKind.AUTH_FAILURE,
        raw=f"auth event {seconds}",
        username=user,
        service="sshd",
    )


def http_event(
    seconds: int,
    path: str,
    status: int = 404,
    ip: str = "203.0.113.47",
    agent: str = "curl/8.1",
):
    return LogEvent(
        timestamp=BASE + timedelta(seconds=seconds),
        source_ip=ip,
        kind=EventKind.HTTP_REQUEST,
        raw=f"http {path}",
        path=path,
        method="GET",
        status=status,
        user_agent=agent,
        service="http",
    )


class TestForcaBruta:
    def test_detecta_rajada_dentro_da_janela(self):
        events = [auth_event(i * 10) for i in range(6)]
        findings = BruteForceDetector().run(events, CONFIG)
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH
        assert findings[0].source_ip == "203.0.113.47"

    def test_falhas_espalhadas_nao_disparam(self):
        # 6 falhas, mas uma por hora: usuário esquecido, não ataque.
        events = [auth_event(i * 3600) for i in range(6)]
        assert BruteForceDetector().run(events, CONFIG) == []

    def test_abaixo_do_limiar_nao_dispara(self):
        events = [auth_event(i * 10) for i in range(4)]
        assert BruteForceDetector().run(events, CONFIG) == []

    def test_ips_diferentes_sao_contados_separadamente(self):
        events = [auth_event(i * 10, ip=f"203.0.113.{i}") for i in range(6)]
        assert BruteForceDetector().run(events, CONFIG) == []

    def test_limiar_configuravel(self):
        events = [auth_event(i * 10) for i in range(3)]
        findings = BruteForceDetector().run(events, DetectorConfig(brute_force_threshold=3))
        assert len(findings) == 1


class TestLoginAposFalhas:
    def test_sucesso_depois_de_rajada_e_critico(self):
        events = [auth_event(i * 10) for i in range(6)]
        events.append(auth_event(70, ok=True, user="deploy"))
        findings = CredentialStuffingDetector().run(events, CONFIG)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert "deploy" in findings[0].description

    def test_sucesso_sem_falhas_anteriores_e_normal(self):
        events = [auth_event(0, ok=True, user="victor")]
        assert CredentialStuffingDetector().run(events, CONFIG) == []

    def test_poucas_falhas_antes_do_sucesso_nao_disparam(self):
        events = [auth_event(0), auth_event(10), auth_event(20, ok=True)]
        assert CredentialStuffingDetector().run(events, CONFIG) == []


class TestCaminhosSensiveis:
    def test_varredura_bloqueada_e_alta(self):
        events = [http_event(i, p) for i, p in enumerate(["/.env", "/.git/config", "/admin"])]
        findings = SensitivePathDetector().run(events, CONFIG)
        assert findings[0].severity is Severity.HIGH

    def test_arquivo_servido_com_200_e_critico(self):
        events = [http_event(0, "/.env", status=200)]
        findings = SensitivePathDetector().run(events, CONFIG)
        assert findings[0].severity is Severity.CRITICAL
        assert "/.env" in findings[0].description

    def test_caminho_comum_nao_dispara(self):
        events = [http_event(0, "/planos", status=200)]
        assert SensitivePathDetector().run(events, CONFIG) == []


class TestFerramentaDeVarredura:
    def test_identifica_sqlmap_pelo_user_agent(self):
        events = [http_event(0, "/q", agent="sqlmap/1.8#stable")]
        findings = ScannerAgentDetector().run(events, CONFIG)
        assert len(findings) == 1
        assert "sqlmap" in findings[0].description

    def test_navegador_comum_nao_dispara(self):
        events = [http_event(0, "/", agent="Mozilla/5.0 Chrome/129.0")]
        assert ScannerAgentDetector().run(events, CONFIG) == []


class TestEnumeracao:
    def test_muitos_404_disparam(self):
        events = [http_event(i, f"/p{i}") for i in range(20)]
        findings = EnumerationDetector().run(events, CONFIG)
        assert len(findings) == 1
        assert findings[0].event_count == 20

    def test_poucos_404_nao_disparam(self):
        events = [http_event(i, f"/p{i}") for i in range(5)]
        assert EnumerationDetector().run(events, CONFIG) == []


class TestAnalyze:
    def test_ordena_do_mais_grave_para_o_menos(self):
        events = [auth_event(i * 10) for i in range(6)]
        events.append(auth_event(70, ok=True))
        events += [http_event(100 + i, f"/p{i}") for i in range(20)]
        findings = analyze(events)
        ranks = [f.severity.rank for f in findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_log_limpo_nao_gera_achado(self):
        events = [http_event(i, "/", status=200, agent="Mozilla/5.0") for i in range(10)]
        assert analyze(events) == []
