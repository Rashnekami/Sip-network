# Sip-Network

Analisador passivo de **SIP / SDP / RTP / RTCP** para arquivos **PCAP e PCAPNG**.

Pensado para técnicos de NOC de operadoras VoIP, como módulo do checktecnico ou de forma isolada. A versão 2.x foi desenhada para evitar diagnósticos enganosos comuns em analisadores simplificados: não assume que RTP está em uma faixa fixa de portas, não chama inter-packet gap de latência, não considera comunicação entre redes privadas um erro de NAT e não calcula MOS apenas a partir de jitter.

## Principais recursos

- PCAP clássico e PCAPNG, inclusive timestamps em microssegundos/nanosegundos.
- Ethernet, VLAN/QinQ, PPPoE, Linux SLL/SLL2, IPv4 e IPv6.
- SIP sobre UDP e reassembly básico de SIP sobre TCP.
- Agrupamento por `Call-ID`, `CSeq`, método e `Via branch`.
- Ladder por chamada e tempos até 180/183/2xx.
- Detecção correta de **ACK ausente somente para 2xx do INVITE**.
- Retransmissões SIP e respostas finais 4xx/5xx/6xx.
- SDP com `c=`, `m=audio`, `rtpmap`, `fmtp`, `ptime`, `rtcp`, direção e ICE candidates.
- RTP validado por cabeçalho + SDP, com heurística apenas como fallback.
- Streams separados por SSRC e direção.
- Sequence number estendido com rollover 16-bit, duplicados e reordenação.
- Perda RTP baseada em sequência esperada versus única recebida.
- Jitter de interchegada conforme RFC 3550.
- Codec e clock rate por SDP/RTP profile; clock inferido quando necessário.
- Ptime observado, bitrate, gaps e eventos DTMF `telephone-event`.
- RTCP SR/RR e RTT quando os campos LSR/DLSR permitem cálculo.
- MOS/R-Factor operacional por E-model, sem inventar one-way delay quando ele não é mensurável.
- Diagnóstico de RTP ausente, one-way audio, packet loss, jitter, reorder e duplicação.
- NAT analisado por `Contact`, endereço observado e SDP, sem falsos positivos por simples roteamento entre sub-redes privadas.
- Remontagem de fragmentos IPv4/IPv6 (INVITE com SDP grande) e leitura de DSCP.
- Modelo de diálogo RFC 3261: forking, ACK por diálogo, re-INVITE, hold/resume, REFER, desafios 401/407.
- Desfecho da chamada (atendida, ocupado, cancelada, sem resposta, 5xx, codec incompatível…), PDD, setup, ring, duração,
  lado que desligou e causa Q.850 (header Reason ou mapeamento RFC 3398).
- KPIs de NOC: ASR, NER, SER/SEER/ISA (RFC 6076), ACD, PDD médio e p95, por tronco/destino de sinalização.
- Registros: estado por AOR, desafios, senha recusada, REGISTER sem resposta, atraso de registro.
- Segurança: scanners por User-Agent, força bruta de senha, enumeração de ramais, varredura OPTIONS,
  flood por método e fraude internacional (IRSF).
- Mídia: perda reportada pelo receptor (RTCP), gaps de áudio, PT não negociado, RTP para endereço fora do SDP,
  troca de SSRC, RTP após BYE, áudio começando atrasado, DSCP do RTP e da sinalização, DTMF por dígito.
- Rede: ICMP destino/porta inalcançável associado ao fluxo SIP/RTP que o provocou.
- Limites de diagnóstico ajustáveis por cliente/tronco (`Thresholds`).
- Dashboard Streamlit com ladder gráfico, CLI (JSON ou resumo em texto) e biblioteca sem dependências externas.
- Processamento local: o arquivo não precisa sair do servidor onde o app está rodando.

## Limites importantes

O objetivo é diagnóstico operacional de captura, não substituir um analisador protocolar completo como Wireshark/tshark.

- **SIP TLS e SRTP** não podem ser inspecionados sem as chaves necessárias.
- Um PCAP capturado em apenas um ponto normalmente **não mede atraso boca-ouvido**. Por isso o MOS não inventa esse valor. Quando um RTT válido é derivado de RTCP, o sistema usa `RTT/2` como estimativa e deixa isso explícito.
- NAT/SBC/B2BUA podem reescrever sinalização e mídia. As regras retornam indícios e nível de confiança, não uma afirmação absoluta sem evidência.
- Ausência de BYE no fim do arquivo não significa falha: a captura pode ter acabado antes da chamada.
- O E-model é uma **estimativa operacional**. Perfis de codec fora dos perfis narrowband mais conhecidos são marcados com confiança menor.

## Uso como biblioteca (integração com o checktecnico)

O motor de análise usa só a biblioteca padrão do Python e não depende do Streamlit:

```python
from sip_network import analyze_bytes, Thresholds

result = analyze_bytes(open("captura.pcapng", "rb").read(), "captura.pcapng",
                       thresholds=Thresholds(pdd_warning_ms=4000))
result.kpis["calls"]["asr_pct"]
[d for d in result.diagnostics if d.severity == "critical"]
payload = result.to_dict(include_messages=False)   # JSON estável, com schema_version
```

Detalhes do contrato em [`docs/INTEGRACAO.md`](docs/INTEGRACAO.md).

## Instalação local

```bash
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate      # Windows
pip install -r requirements.txt
streamlit run app.py
```

Abra `http://localhost:8501`.

## Docker

```bash
docker compose up -d --build
```

Interface: `http://IP_DO_SERVIDOR:8501`

Antes de expor fora de uma rede confiável, defina autenticação simples por token:

```bash
export SIP_NETWORK_ACCESS_TOKEN="troque-por-um-token-forte"
docker compose up -d --build
```

O compose usa container read-only, `tmpfs`, remove capabilities Linux e ativa `no-new-privileges`.

## CLI

```bash
pip install .
sip-network captura.pcapng --pretty
sip-network captura.pcap --json relatorio.json
sip-network captura.pcap --summary              # resumo em texto para o técnico
sip-network captura.pcap --fail-on critical     # sai com código 2 se houver achado crítico
```

Ou:

```bash
python -m sip_network captura.pcapng --json relatorio.json
```

## Como o RTP é identificado

1. O parser valida o cabeçalho RTP versão 2.
2. Endpoints e payload types anunciados no SDP aumentam fortemente a confiança.
3. Se não houver SDP utilizável, é permitido fallback heurístico somente quando existe sequência coerente de pacotes RTP.
4. RTCP é separado de RTP antes da análise.

Isso evita a regra frágil `UDP 10000-20000 = RTP`.

## Jitter RFC 3550

Para cada SSRC, o cálculo usa o tempo de chegada convertido para unidades do clock RTP e o timestamp RTP do pacote:

```text
transit = arrival - rtp_timestamp
D = transit_atual - transit_anterior
J = J + (abs(D) - J) / 16
```

O valor final é convertido novamente para milissegundos pelo clock do codec.

## Perda RTP

A sequência RTP é 16-bit e pode passar de `65535` para `0`. O analisador cria uma sequência estendida, diferencia:

- pacote novo;
- pacote duplicado;
- pacote fora de ordem;
- rollover;
- número esperado que nunca apareceu.

A perda é calculada apenas sobre sequências únicas esperadas.

## MOS / E-model

O fluxo usa:

```text
R = 93.2 - Id - Ie_eff
```

com impairment de codec/perda e burst ratio. O MOS é derivado do R-Factor pela curva do G.107.

Quando não existe uma medição defensável de atraso:

```text
Id = 0
MOS note = "sem atraso boca-ouvido"
```

Ou seja, o valor é deliberadamente rotulado como uma estimativa parcial em vez de apresentar precisão falsa.

## Diagnósticos

Exemplos:

| Área | Códigos |
|---|---|
| Sinalização | `SIP_FINAL_FAILURE`, `SIP_NO_RESPONSE`, `SIP_MISSING_ACK`, `SIP_DROP_32S`, `SIP_SESSION_TIMER_DROP`, `SIP_HIGH_PDD`, `SIP_AUTH_LOOP`, `SIP_RETRANSMISSIONS`, `SIP_FORKED_ANSWER`, `SIP_SHORT_CALL`, `SIP_TERMINATION_NOT_SEEN`, `SIP_HOLD`, `SIP_TRANSFER`, `SIP_DSCP` |
| Mídia | `NO_RTP_AFTER_ANSWER`, `ONE_WAY_AUDIO`, `MEDIA_START_DELAY`, `RTP_AFTER_BYE`, `RTP_PACKET_LOSS`, `RTCP_REMOTE_LOSS`, `RTP_JITTER`, `LOW_MOS`, `RTP_GAP`, `RTP_PT_NOT_NEGOTIATED`, `MEDIA_DEST_MISMATCH`, `RTP_SSRC_CHANGE`, `RTP_DSCP`, `RTP_REORDER`, `RTP_DUPLICATES` |
| NAT | `NAT_CONTACT_MISMATCH`, `PRIVATE_SDP_OVER_PUBLIC_SIGNALING` |
| Rede | `ICMP_UNREACHABLE` |
| Registro | `REGISTER_FAILED`, `REGISTER_NO_RESPONSE` |
| Segurança | `SEC_SCANNER`, `SEC_BRUTE_FORCE`, `SEC_ENUMERATION`, `SEC_OPTIONS_SWEEP`, `SEC_RATE`, `SEC_SCAN`, `SEC_TOLL_FRAUD` |

Cada achado contém severidade, confiança e evidências associadas.

## Estrutura

```text
Sip-network/
├── app.py                  # dashboard Streamlit (opcional)
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
├── sip_network/
│   ├── capture.py          # pcap/pcapng, link layers, IP, fragmentos
│   ├── sip.py              # parser SIP, TCP, chamadas e diálogos
│   ├── sdp.py
│   ├── rtp.py / rtcp.py    # qualidade de mídia
│   ├── emodel.py           # MOS/R-factor
│   ├── registrations.py    # REGISTER e transações
│   ├── security.py         # ataques e fraude
│   ├── kpi.py              # ASR, NER, SEER, ACD, PDD
│   ├── network.py          # fluxos e ICMP
│   ├── diagnostics.py      # regras de diagnóstico
│   ├── ladder.py           # ladder SVG reutilizável
│   ├── q850.py
│   ├── config.py           # Thresholds
│   └── engine.py           # ponto de entrada
├── tools/make_demo_pcap.py # gera uma captura de demonstração
└── tests/
```

## Próximas evoluções úteis

- RTP/RTCP XR mais completo.
- G.107.1 específico para wideband e perfis de codec parametrizáveis.
- TLS/SRTP com importação opcional de segredos/chaves quando tecnicamente possível.
- Exportação PDF/HTML.
- Banco de assinaturas de falha SIP por fabricante/SBC.
- Leitura em streaming para capturas acima de 250 MB (hoje a captura inteira fica em memória).
- SIP sobre WebSocket e ingestão HEP (Homer) para análise ao vivo.
- Autenticação integrada por usuário/perfil além do token opcional atual.
- Captura ao vivo via `libpcap` em um agente separado com privilégios mínimos.
- Comparação de capturas de dois pontos para calcular delay e localizar onde a perda nasce.

## Referências técnicas

- RFC 3261 — SIP
- RFC 3550 — RTP / RTCP e jitter
- RFC 3398 / RFC 3326 — mapeamento SIP↔Q.850 e header Reason
- RFC 4733 — eventos DTMF
- RFC 6076 — métricas de desempenho SIP (SER, SEER, ISA, SRD)
- RFC 3551 — RTP Audio/Video Profile
- ITU-T G.107 — E-model

