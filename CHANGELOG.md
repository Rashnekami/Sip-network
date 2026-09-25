# Changelog

## 2.1.0

Evolução para uso em NOC de operadoras VoIP (módulo do checktecnico).

### Corrigido

- INVITE desafiado com 401/407 e reenviado não é mais classificado como falha: o resultado vem do último INVITE.
- 487 após CANCEL é chamada cancelada, não falha crítica.
- ACK ausente é verificado por diálogo (to-tag), cobrindo forking.
- REGISTER/OPTIONS não aparecem mais como "chamadas".
- INVITE com SDP grande fragmentado em UDP era analisado truncado.

### Adicionado

- Remontagem de fragmentos IPv4 e IPv6; DSCP por pacote.
- Modelo de diálogo: forking, re-INVITE, hold/resume, REFER, desafios de autenticação.
- Desfecho da chamada, PDD, setup, ring, duração, lado que desligou e causa Q.850 (Reason ou RFC 3398).
- KPIs: ASR, NER, SER, SEER, ISA, ACD, PDD médio/p95, por tronco e por destino com falha.
- Registros por AOR, e segurança: scanners, força bruta, enumeração de ramais, varredura OPTIONS e fraude internacional.
- Diagnósticos: queda em ~32s por ACK, session timer, PDD alto, INVITE sem resposta, RTP após BYE, áudio atrasado,
  gaps, PT não negociado, RTP fora do SDP, troca de SSRC, perda remota por RTCP, DSCP, ICMP inalcançável.
- DTMF por dígito (RFC 4733).
- `Thresholds` configuráveis, `analyze_file`, `to_dict(include_messages=False)` e `schema_version`.
- Ladder SVG reutilizável, abas de KPI e registros e cache no Streamlit.
- CLI `--summary`, `--no-messages` e `--fail-on`.
- Motor sem dependências externas (UI como extra `.[ui]`), CI no GitHub Actions e testes com cenários completos.
- API HTTP (`api.py`, `Dockerfile.api`, extra `.[api]`) com token, limite de upload e de análises simultâneas, e guias de deploy e de integração com Lovable/Supabase.

## 2.0.0

Reescrita técnica do conceito Sip-Network com foco em diagnóstico defensável.

### Corrigido / substituído

- RTP não depende mais da faixa UDP 10000–20000.
- Jitter não usa mais desvio padrão do intervalo entre pacotes; usa RFC 3550.
- MOS não é mais escolhido por faixas arbitrárias de jitter.
- Perda RTP trata rollover de sequence number, duplicados e reorder.
- `200 OK` genérico não gera ACK ausente; a verificação é correlacionada ao INVITE/CSeq.
- Comunicação entre duas sub-redes privadas não é classificada automaticamente como erro de NAT.
- Inter-packet gap não é apresentado como latência.
- PCAPNG deixa de ser anunciado sem suporte: há parser funcional de Enhanced Packet Blocks.
- IPv6 e VLAN/QinQ passam a ser decodificados.

### Adicionado

- SIP sobre TCP com reassembly básico.
- SDP offer/answer e codecs dinâmicos.
- RTP por SSRC.
- RTCP Receiver Reports e RTT quando calculável.
- E-model operacional com indicação explícita de limitações.
- one-way audio, RTP ausente, NAT/SDP mismatch, retransmissões SIP e falhas finais.
- DTMF telephone-event.
- exportação JSON/CSV.
- CLI.
- Docker endurecido e token de acesso opcional.
- testes de regressão para PCAP, PCAPNG, TCP SIP, jitter, perda, duplicação e rollover.
