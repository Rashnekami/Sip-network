# Changelog

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
