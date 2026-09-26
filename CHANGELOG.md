# Changelog

## 2.3.0

### Adicionado

- Análise WebRTC sem chaves (`webrtc.py`, `websocket.py`, saída `webrtc`): SIP sobre WebSocket entra no motor de chamadas
  como transporte `WS`; sessões ICE por par de ice-ufrag com pares de candidatos, nomeação e consentimento; servidor STUN;
  TURN (Allocate, falhas e mídia dentro de ChannelData/Send/Data); handshake DTLS com alertas e use_srtp; SRTP medido
  pelo cabeçalho (perda, jitter, direção). 20 códigos `WEBRTC_*` e categoria `webrtc` nos diagnósticos e gráficos.
- SDP: `a=ice-ufrag`, `a=fingerprint`, `a=setup`, `a=rtcp-mux` e candidatos ICE; m=video; endpoints de mídia por candidato.
- `rtp_streams[]`: `media_kind`, `secure`, `codec_inferred` (Opus inferido por clock de 48 kHz), `webrtc_session`.
- `IP_FRAGMENTS_LOST`: datagrama fragmentado com parte perdida (INVITE grande por UDP).
- Laboratório de 87 pcaps sintéticos com gabarito (`tests/lab.py`, `tests/test_lab.py`, `tools/make_lab_pcaps.py`).
- Aba WebRTC no Streamlit.

### Corrigido (encontrado pelo laboratório)

- Gaps de RTP durante espera (hold) viravam `RTP_GAP`; um salto de timestamp após pausa ou marker inflava o jitter.
- `NAT_ONE_WAY_AUDIO` disparava em rede privada porque o Via das respostas era lido como se fosse do remetente.
- `SIP_ALG_CONTENT_LENGTH` disparava em mensagem truncada/malformada e em INVITE fragmentado; `SIP_ALG_SDP_REWRITE`
  disparava para todo navegador (o= 127.0.0.1).
- `NAT_PRIVATE_SDP` em chamada não atendida, ou com áudio passando nos dois sentidos, deixou de ser alerta.
- Cada INVITE/REGISTER de uma origem atacante (flood, varredura, força bruta, flood distribuído) gerava um diagnóstico
  próprio; agora o ataque aparece uma vez, no alerta de segurança/DDoS.
- Troca de SSRC contava áudio e vídeo do mesmo 5-tupla (BUNDLE) como troca.
- RTCP de fluxos SRTP (blocos criptografados) não é mais lido como perda/jitter remotos.

### Alterado

- `schema_version` 2.3 (campos novos apenas).

## 2.2.0

### Adicionado

- Motor de NAT (`nat.py`, saída `nat[]`): aparelho atrás de NAT/CGNAT, falta de rport, expires longo demais para o NAT,
  SIP ALG por Content-Length divergente e por SDP reescrito pela metade, IP privado no SDP, RTP de endereço fora do SDP
  (latching) e áudio unidirecional causado por NAT.
- Motor de DDoS (`ddos.py`, saída `ddos[]`): volumétrico com linha de base, SYN flood, ICMP flood, reflexão/amplificação
  e flood SIP distribuído. O RTP das chamadas não conta como ataque.
- `category` em cada diagnóstico, `kpis.charts` para gráficos de rosca e `kpis.traffic_timeline`.
- Abas NAT e DDoS no Streamlit; cenários de NAT e SYN flood na captura de demonstração.

### Alterado

- `schema_version` 2.2. As regras `NAT_CONTACT_MISMATCH` e `PRIVATE_SDP_OVER_PUBLIC_SIGNALING` foram substituídas por
  `DEVICE_BEHIND_NAT` e `NAT_PRIVATE_SDP`.

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
