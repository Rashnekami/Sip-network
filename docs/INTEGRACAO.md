# Integração (checktecnico e outros sistemas)

O pacote `sip_network` é uma biblioteca Python 3.11+ **sem dependências externas**. A interface Streamlit (`app.py`) é só um cliente dela; o checktecnico pode chamar a biblioteca diretamente, via CLI ou empacotá-la num serviço próprio.

## Pontos de entrada

```python
from sip_network import analyze_bytes, analyze_file, Thresholds

result = analyze_bytes(data: bytes, filename: str = "capture", thresholds: Thresholds = DEFAULT_THRESHOLDS)
result = analyze_file("/caminho/captura.pcapng")
```

`result` é um `AnalysisResult` (dataclasses em `sip_network/models.py`). Para enviar a outro serviço:

```python
payload = result.to_dict(include_messages=False)  # dict pronto para json.dumps(default=str)
```

`include_messages=False` remove headers/corpo SIP completos de cada mensagem e reduz muito o tamanho. Use `True` quando a tela precisar mostrar a mensagem crua.

CLI equivalente:

```bash
sip-network captura.pcap --no-messages --json saida.json
sip-network captura.pcap --summary --fail-on critical   # exit 2 se houver crítico
```

## Contrato do JSON (`schema_version` = "2.1")

| Chave | Conteúdo |
|---|---|
| `schema_version` | versão do contrato; muda de major quando um campo existente muda de significado |
| `capture` | arquivo, pacotes, duração, contagens IPv4/IPv6/VLAN/fragmentos, observações do parser |
| `kpis.calls` | `attempts`, `answered`, `asr_pct`, `ner_pct`, `ser_pct`, `seer_pct`, `isa_pct`, `acd_s`, `pdd_avg_ms`, `pdd_p95_ms`, `outcomes`, `final_codes`, `q850_causes`, `disconnect_side`… |
| `kpis.by_peer` | mesmos KPIs por IP de destino da sinalização (tronco/SBC) |
| `kpis.failing_destinations` | destinos com mais falhas e códigos |
| `kpis.media` | MOS médio/mínimo, faixas de MOS, perda média, jitter p95, codecs, DSCP |
| `kpis.registrations` | AORs, registrados, falhando, sem resposta, atraso médio de registro |
| `kpis.icmp_errors` | ICMP destino/porta inalcançável associado ao fluxo original |
| `calls[]` | uma por Call-ID com INVITE: `outcome`, `final_status`, `q850_cause`, `pdd_ms`, `setup_time_ms`, `duration_s`, `disconnect_side`, `dialogs`, `hold_events`, `transfers`, `media_endpoints`, `messages`… |
| `rtp_streams[]` | um por direção+SSRC: perda, jitter, MOS, R-factor, RTCP remoto, DSCP, gaps, DTMF… |
| `registrations[]` | um por AOR+origem: estado, tentativas, desafios, senha recusada, expires |
| `diagnostics[]` | `severity` (critical/warning/info), `code`, `title`, `detail`, `confidence`, `call_id`, `stream_id`, `evidence` |
| `security[]` | alertas de ataque/fraude com `type`, `source_ip` e evidências |
| `network_flows[]` | fluxos L3/L4 com pacotes, bytes, gaps e RST |

Valores de `outcome`: `answered`, `busy`, `no_answer`, `cancelled`, `rejected`, `not_found`, `auth_failed`, `media_negotiation_failed`, `server_error`, `timeout`, `no_response`, `redirected`, `client_error`, `global_failure`, `in_progress`, `unknown`.

Os `code` de diagnóstico são estáveis e podem ser usados para regras no checktecnico (abrir chamado, notificar, agrupar). A lista completa está no README.

## Limites por cliente

```python
Thresholds(
    pdd_warning_ms=5000, pdd_critical_ms=10000,
    loss_warning_pct=2.0, loss_critical_pct=5.0,
    jitter_warning_ms=30, mos_warning=3.6,
    expected_rtp_dscp=46, home_country_code="55",
    brute_force_failures=10, toll_fraud_destinations=5,
)
```

Todos os campos estão em `sip_network/config.py`.

## Recomendações de implantação

- Rodar a análise fora do processo web (fila/worker), porque capturas grandes levam segundos e ocupam memória proporcional ao arquivo.
- Guardar o JSON sem mensagens para histórico e o PCAP original à parte, se a política de retenção permitir. Capturas SIP contêm números de telefone e, em SIP sem TLS, podem conter credenciais em hash (Digest): trate como dado sensível.
- Fixar a versão do pacote e validar `schema_version` ao consumir.
