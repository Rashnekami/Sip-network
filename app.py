from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime

import pandas as pd
import streamlit as st

from sip_network import analyze_bytes

st.set_page_config(page_title="Sip-Network 2.0", page_icon="☎️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 1.4rem; padding-bottom: 3rem;}
[data-testid="stMetricValue"] {font-size: 1.65rem;}
.sn-critical {border-left:4px solid #d33;padding:.65rem 1rem;background:rgba(211,51,51,.08);margin:.4rem 0}
.sn-warning {border-left:4px solid #e6a700;padding:.65rem 1rem;background:rgba(230,167,0,.08);margin:.4rem 0}
.sn-info {border-left:4px solid #4b8bf4;padding:.65rem 1rem;background:rgba(75,139,244,.08);margin:.4rem 0}
</style>
""", unsafe_allow_html=True)

st.title("☎️ Sip-Network 2.0")
st.caption("Análise passiva de SIP, SDP, RTP e RTCP em PCAP/PCAPNG — processado localmente no servidor.")

access_token = os.getenv("SIP_NETWORK_ACCESS_TOKEN")
if access_token:
    if not st.session_state.get("authenticated"):
        supplied = st.text_input("Token de acesso", type="password")
        if st.button("Entrar", type="primary"):
            if supplied == access_token:
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Token inválido.")
        st.stop()

uploaded = st.file_uploader("Captura de rede", type=["pcap", "pcapng", "cap"], help="PCAP clássico ou PCAPNG. SIP TLS/SRTP não podem ser inspecionados sem descriptografia.")
if not uploaded:
    st.info("Envie uma captura para iniciar. O analisador não usa faixa fixa de porta para RTP: prioriza SDP e valida o cabeçalho RTP.")
    st.stop()

if uploaded.size > 250 * 1024 * 1024:
    st.error("Arquivo acima de 250 MB. Para capturas maiores, filtre o intervalo/protocolos antes da análise.")
    st.stop()

try:
    with st.spinner("Analisando captura…"):
        result = analyze_bytes(uploaded.getvalue(), uploaded.name)
except Exception as exc:
    st.error(f"Falha ao analisar: {exc}")
    st.stop()

cap = result.capture
cols = st.columns(6)
cols[0].metric("Pacotes", f"{cap['packets']:,}".replace(",", "."))
cols[1].metric("Duração", f"{cap['duration_s']:.1f}s")
cols[2].metric("SIP", cap["sip_messages"])
cols[3].metric("Chamadas", cap["sip_calls"])
cols[4].metric("RTP", cap["rtp_streams"])
critical = sum(1 for d in result.diagnostics if d.severity == "critical")
cols[5].metric("Críticos", critical)

summary, calls_tab, rtp_tab, diag_tab, net_tab, sec_tab = st.tabs(["Resumo", "Chamadas SIP", "RTP / Qualidade", "Diagnósticos", "Rede", "Segurança SIP"])

with summary:
    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("Achados prioritários")
        if not result.diagnostics:
            st.success("Nenhum problema evidente foi encontrado pelas regras atuais.")
        for d in result.diagnostics[:12]:
            st.markdown(f'<div class="sn-{d.severity}"><b>{d.title}</b><br>{d.detail}<br><small>Confiança: {d.confidence}</small></div>', unsafe_allow_html=True)
    with c2:
        st.subheader("Captura")
        st.write({
            "IPv4": cap["ipv4_packets"], "IPv6": cap["ipv6_packets"], "VLAN": cap["vlan_packets"],
            "Fragmentados": cap["fragmented_packets"], "Bytes": cap["bytes"],
        })
        if cap.get("parse_notes"):
            with st.expander("Observações do parser"):
                for n in cap["parse_notes"]: st.write("•", n)

with calls_tab:
    rows = []
    for c in result.calls:
        setup_ms = (c.connected_at - c.started_at) * 1000 if c.connected_at else None
        ring_ms = (c.ringing_at - c.started_at) * 1000 if c.ringing_at else None
        rows.append({
            "Call-ID": c.call_id, "De": c.from_uri, "Para": c.to_uri, "Final": c.final_status,
            "Setup ms": round(setup_ms,1) if setup_ms is not None else None,
            "180 ms": round(ring_ms,1) if ring_ms is not None else None,
            "Conectada": c.connected, "ACK ausente": c.missing_ack, "Término visto": c.termination_observed,
            "Retransmissões": c.retransmissions, "Mídias SDP": len(c.media_endpoints),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    if result.calls:
        selected = st.selectbox("Ladder da chamada", [c.call_id for c in result.calls])
        call = next(c for c in result.calls if c.call_id == selected)
        ladder = [{"t + ms": round((m.timestamp-call.started_at)*1000,1), "Origem":f"{m.src_ip}:{m.src_port}", "Destino":f"{m.dst_ip}:{m.dst_port}", "Mensagem":m.start_line, "CSeq":f"{m.cseq_number or ''} {m.cseq_method or ''}"} for m in call.messages]
        st.dataframe(pd.DataFrame(ladder), use_container_width=True, hide_index=True)
        with st.expander("SDP / endpoints de mídia"):
            st.json(call.media_endpoints)

with rtp_tab:
    rows = [asdict(s) for s in result.rtp_streams]
    if rows:
        df = pd.DataFrame(rows)
        show = df[["stream_id","call_id","src_ip","src_port","dst_ip","dst_port","codec","packets","loss_percent","jitter_ms","mos","r_factor","rtt_ms","ptime_ms","duplicates","out_of_order"]]
        st.dataframe(show, use_container_width=True, hide_index=True)
        st.caption("Jitter: RFC 3550. MOS: estimativa operacional por E-model; quando RTT RTCP não está disponível, atraso boca-ouvido não é inventado e não entra no cálculo.")
    else:
        st.info("Nenhum fluxo RTP confiável foi detectado.")

with diag_tab:
    severity = st.multiselect("Severidade", ["critical","warning","info"], default=["critical","warning","info"])
    for d in [x for x in result.diagnostics if x.severity in severity]:
        st.markdown(f'<div class="sn-{d.severity}"><b>{d.code} — {d.title}</b><br>{d.detail}<br><small>Call-ID: {d.call_id or "—"} | Stream: {d.stream_id or "—"} | confiança: {d.confidence}</small></div>', unsafe_allow_html=True)
        if d.evidence:
            st.json(d.evidence, expanded=False)

with net_tab:
    if result.network_flows:
        st.dataframe(pd.DataFrame(result.network_flows[:500]), use_container_width=True, hide_index=True)
        st.caption("Inter-packet gap não é chamado de latência. Latência só é exibida quando existe uma medição correlacionável.")

with sec_tab:
    if result.security:
        st.dataframe(pd.DataFrame(result.security), use_container_width=True, hide_index=True)
    else:
        st.success("Nenhum padrão simples de flood/scan SIP foi identificado.")

download_cols = st.columns(3)
payload = json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str).encode("utf-8")
download_cols[0].download_button("Baixar JSON", payload, file_name=f"{uploaded.name}.sip-network.json", mime="application/json")
call_csv = pd.DataFrame([{
    "call_id": c.call_id, "from": c.from_uri, "to": c.to_uri, "final_status": c.final_status,
    "connected": c.connected, "missing_ack": c.missing_ack, "retransmissions": c.retransmissions
} for c in result.calls]).to_csv(index=False).encode("utf-8")
download_cols[1].download_button("Chamadas CSV", call_csv, file_name=f"{uploaded.name}.calls.csv", mime="text/csv")
rtp_csv = pd.DataFrame([asdict(s) for s in result.rtp_streams]).to_csv(index=False).encode("utf-8")
download_cols[2].download_button("RTP CSV", rtp_csv, file_name=f"{uploaded.name}.rtp.csv", mime="text/csv")
