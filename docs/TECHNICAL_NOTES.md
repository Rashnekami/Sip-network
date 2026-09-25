# Notas técnicas — Sip-Network 2.0

## O que o sistema pode afirmar com boa confiança

- sequência SIP observada na captura;
- respostas e CSeq correlacionados;
- RTP versão 2 válido e SSRC observado;
- perda inferida pela sequência RTP recebida no ponto de captura;
- duplicação e reordenação observadas no ponto de captura;
- jitter de interchegada conforme RFC 3550 no ponto de captura;
- endpoints e codecs anunciados em SDP;
- inconsistência entre endereço observado, Contact e SDP;
- RTCP Receiver Reports presentes na captura.

## O que depende do ponto de captura

Perda, jitter e one-way audio descrevem o que o **sensor/captura viu**. Uma captura feita somente do lado A não consegue provar automaticamente onde, ao longo de toda a rota, o defeito nasceu.

A forma mais forte de localizar problema é comparar capturas sincronizadas em dois pontos. Se o pacote existe no ponto A e some antes do ponto B, a perda está no trecho intermediário.

## Latência

Intervalo entre pacotes não é latência. Por isso o dashboard usa `inter-packet gap` para tráfego genérico.

Para mídia, uma captura passiva em um único ponto não conhece por si só o atraso de propagação fim a fim. RTT pode ser inferido de RTCP em determinadas condições; o sistema marca esse valor como estimativa.

## NAT

Duas redes RFC1918 diferentes não implicam erro de NAT. Roteamento entre VLANs/sub-redes privadas é perfeitamente legítimo.

O diagnóstico observa sinais mais úteis:

- Contact privado versus origem pública observada;
- Via `received`/`rport`;
- SDP privado atravessando sinalização pública;
- RTP presente somente em uma direção;
- RTP ausente após uma chamada atendida.

Mesmo assim, SBC/B2BUA/media relay podem tornar a topologia legítima. Por isso os achados têm nível de confiança.

## MOS

O valor exibido é uma estimativa operacional por E-model, não uma medição subjetiva real.

Quando não existe atraso defensável, o sistema não fabrica um número. O componente de delay é omitido e a observação fica registrada no stream.

## Tráfego criptografado

- SIP/TLS: cabeçalhos e SDP não estão disponíveis sem descriptografia.
- SRTP: conteúdo de áudio/DTMF não pode ser interpretado sem chaves, embora metadados externos possam continuar visíveis dependendo da captura.
