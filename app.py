from __future__ import annotations

import json
import os
from dataclasses import asdict

import pandas as pd
import streamlit as st

from sip_network import Thresholds, analyze_bytes
from sip_network.ladder import ladder_svg

st.set_page_config(page_title="Sip-Network", page_icon="☎️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 1.4rem; padding-bottom: 3rem;}
[data-testid="stMetricValue"] {font-size: 1.65rem;}
.sn-critical {border-left:4px solid #d33;padding:.65rem 1rem;background:rgba(211,51,51,.08);margin:.4rem 0}
.sn-warning {border-left:4px solid #e6a700;padding:.65rem 1rem;background:rgba(230,167,0,.08);margin:.4rem 0}
.sn-info {border-left:4px solid #4b8bf4;padding:.65rem 1rem;background:rgba(75,139,244,.08);margin:.4rem 0}
</style>
""", unsafe_allow_html=True)

st.title("☎️ Sip-Network")
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

OUTCOME_PT = {
    "answered": "atendida", "busy": "ocupado", "no_answer": "não atendida", "cancelled": "cancelada",
    "rejected": "recusada", "not_found": "número inexistente", "auth_failed": "falha de autenticação",
    "media_negotiation_failed": "codec incompatível", "server_error": "erro do servidor (5xx)", "timeout": "timeout",
    "no_response": "sem resposta", "redirected": "redirecionada", "client_error": "erro 4xx", "global_failure": "falha 6xx",
    "in_progress": "em andamento", "unknown": "desconhecido",
}


@st.cache_data(show_spinner=False, max_entries=4)
def run_analysis(data: bytes, name: str, th: Thresholds):
    return analyze_bytes(data, name, th)


with st.sidebar:
    st.header("Limites de diagnóstico")
    st.caption("Ajuste por cliente/tronco. Os padrões seguem práticas comuns de operadoras.")
    th = Thresholds(
        pdd_warning_ms=st.number_input("PDD alerta (ms)", 500, 60000, 5000, 500),
        loss_warning_pct=st.number_input("Perda RTP alerta (%)", 0.1, 50.0, 2.0, 0.5),
        jitter_warning_ms=st.number_input("Jitter alerta (ms)", 1.0, 500.0, 30.0, 5.0),
        mos_warning=st.number_input("MOS alerta abaixo de", 1.0, 4.5, 3.6, 0.1),
        expected_rtp_dscp=st.number_input("DSCP esperado no RTP", 0, 63, 46, 1),
        home_country_code=st.text_input("Código do país (fraude internacional)", "55"),
    )

uploaded = st.file_uploader("Captura de rede", type=["pcap", "pcapng", "cap"], help="PCAP clássico ou PCAPNG. SIP TLS/SRTP não podem ser inspecionados sem descriptografia.")
if not uploaded:
    st.info("Envie uma captura para iniciar. O analisador identifica SIP pelo conteúdo (qualquer porta), remonta TCP e fragmentos IP, e associa o RTP às chamadas pelo SDP.")
    st.stop()

if uploaded.size > 250 * 1024 * 1024:
    st.error("Arquivo acima de 250 MB. Para capturas maiores, filtre o intervalo/protocolos antes da análise.")
    st.stop()

try:
    with st.spinner("Analisando captura…"):
        result = run_analysis(uploaded.getvalue(), uploaded.name, th)
except Exception as exc:
    st.error(f"Falha ao analisar: {exc}")
    st.stop()

cap = result.capture
kc = result.kpis.get("calls", {})
km = result.kpis.get("media", {})
fmt = lambda v, suf="": "—" if v is None else f"{v}{suf}"
cols = st.columns(7)
cols[0].metric("Chamadas", kc.get("attempts", 0))
cols[1].metric("ASR", fmt(kc.get("asr_pct"), "%"))
cols[2].metric("NER", fmt(kc.get("ner_pct"), "%"))
cols[3].metric("PDD médio", fmt(kc.get("pdd_avg_ms"), " ms"))
cols[4].metric("ACD", fmt(kc.get("acd_s"), " s"))
cols[5].metric("MOS médio", fmt(km.get("mos_avg")))
cols[6].metric("Críticos", sum(1 for d in result.diagnostics if d.severity == "critical"))

tabs = st.tabs(["Resumo", "Chamadas SIP", "RTP / Qualidade", "Registros", "Diagnósticos", "NAT", "DDoS / Flood", "Segurança SIP", "Rede"])
summary, calls_tab, rtp_tab, reg_tab, diag_tab, nat_tab, ddos_tab, sec_tab, net_tab = tabs

with summary:
    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("Achados prioritários")
        if not [d for d in result.diagnostics if d.severity != "info"]:
            st.success("Nenhum problema crítico ou de alerta pelas regras atuais.")
        for d in result.diagnostics[:15]:
            st.markdown(f'<div class="sn-{d.severity}"><b>{d.title}</b><br>{d.detail}<br><small>{d.code} · Call-ID: {d.call_id or "—"} · confiança: {d.confidence}</small></div>', unsafe_allow_html=True)
    with c2:
        st.subheader("Desfecho das chamadas")
        if kc.get("outcomes"):
            st.dataframe(pd.DataFrame([{"Desfecho": OUTCOME_PT.get(k, k), "Chamadas": v} for k, v in kc["outcomes"].items()]), hide_index=True, use_container_width=True)
        st.write({"SER": fmt(kc.get("ser_pct"), "%"), "SEER": fmt(kc.get("seer_pct"), "%"), "ISA": fmt(kc.get("isa_pct"), "%"),
                  "PDD p95": fmt(kc.get("pdd_p95_ms"), " ms"), "Minutos": kc.get("total_minutes")})
        if kc.get("q850_causes"):
            with st.expander("Causas Q.850"):
                st.write(kc["q850_causes"])
        st.subheader("Captura")
        st.write({"Pacotes": cap["packets"], "Duração (s)": round(cap["duration_s"], 1), "SIP": cap["sip_messages"],
                  "IPv4": cap["ipv4_packets"], "IPv6": cap["ipv6_packets"], "VLAN": cap["vlan_packets"],
                  "Fragmentados": cap["fragmented_packets"]})
        if cap.get("parse_notes"):
            with st.expander("Observações do parser"):
                for n in cap["parse_notes"]: st.write("•", n)
    if result.kpis.get("by_peer"):
        st.subheader("Por destino de sinalização (tronco/SBC)")
        st.dataframe(pd.DataFrame(result.kpis["by_peer"]), hide_index=True, use_container_width=True)
    if result.kpis.get("failing_destinations"):
        with st.expander("Destinos com mais falhas"):
            st.dataframe(pd.DataFrame(result.kpis["failing_destinations"]), hide_index=True, use_container_width=True)

with calls_tab:
    rows = [{
        "Call-ID": c.call_id, "De": c.from_uri, "Para": c.to_uri, "Desfecho": OUTCOME_PT.get(c.outcome, c.outcome),
        "Final": c.final_status, "Q.850": c.q850_cause, "PDD ms": c.pdd_ms, "Setup ms": c.setup_time_ms,
        "Duração s": c.duration_s, "Desligou": c.disconnect_side, "Codecs": ", ".join(c.negotiated_codecs),
        "ACK ausente": c.missing_ack, "Auth": c.auth_challenges, "Re-INVITE": c.reinvites,
        "Retransm.": c.retransmissions, "Origem": c.caller_ip, "Destino": c.callee_ip,
    } for c in result.calls]
    if not rows:
        st.info("Nenhuma chamada (INVITE) encontrada na captura.")
    else:
        only_bad = st.toggle("Somente chamadas com problema", value=False)
        bad_ids = {d.call_id for d in result.diagnostics if d.severity in ("critical", "warning") and d.call_id}
        df = pd.DataFrame(rows)
        if only_bad:
            df = df[df["Call-ID"].isin(bad_ids)]
        st.dataframe(df, use_container_width=True, hide_index=True)
        options = list(df["Call-ID"]) or [c.call_id for c in result.calls]
        selected = st.selectbox("Detalhe da chamada", options)
        call = next(c for c in result.calls if c.call_id == selected)
        for d in [x for x in result.diagnostics if x.call_id == call.call_id]:
            st.markdown(f'<div class="sn-{d.severity}"><b>{d.title}</b><br>{d.detail}</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="overflow-x:auto">{ladder_svg(call)}</div>', unsafe_allow_html=True)
        d1, d2 = st.columns(2)
        with d1:
            st.write({"User-Agent origem": call.caller_user_agent, "User-Agent destino": call.callee_user_agent,
                      "P-Asserted-Identity": call.p_asserted_identity, "Diversion": call.diversion,
                      "Reason": call.reason_header, "Session-Expires": call.session_expires})
        with d2:
            if call.hold_events: st.write("Espera:", call.hold_events)
            if call.transfers: st.write("Transferências:", call.transfers)
            if call.dialogs: st.write("Diálogos:", call.dialogs)
        with st.expander("SDP / endpoints de mídia"):
            st.json(call.media_endpoints)
        with st.expander("Mensagens SIP completas"):
            for m in call.messages:
                st.code(m.start_line + "\n" + "\n".join(f"{k}: {v}" for k, vals in m.raw_headers.items() for v in vals) + ("\n\n" + m.body if m.body else ""), language="http")

with rtp_tab:
    rows = [asdict(s) for s in result.rtp_streams]
    if rows:
        df = pd.DataFrame(rows)
        show = df[["stream_id", "call_id", "src_ip", "src_port", "dst_ip", "dst_port", "codec", "packets", "loss_percent", "jitter_ms",
                   "mos", "r_factor", "max_interarrival_gap_ms", "rtcp_remote_loss_pct", "rtt_ms", "dscp", "ptime_ms", "dtmf_digits",
                   "duplicates", "out_of_order"]]
        st.dataframe(show, use_container_width=True, hide_index=True)
        st.caption("Jitter: RFC 3550. MOS: E-model (G.107) por codec, perda e burst; o atraso só entra quando há RTT de RTCP. "
                   "Perda RTCP remota é a perda que o receptor viu, depois do ponto de captura.")
    else:
        st.info("Nenhum fluxo RTP confiável foi detectado.")

with reg_tab:
    if result.registrations:
        st.dataframe(pd.DataFrame(result.registrations), use_container_width=True, hide_index=True)
    else:
        st.info("Nenhum REGISTER na captura.")

with diag_tab:
    severity = st.multiselect("Severidade", ["critical", "warning", "info"], default=["critical", "warning", "info"])
    for d in [x for x in result.diagnostics if x.severity in severity]:
        st.markdown(f'<div class="sn-{d.severity}"><b>{d.code} — {d.title}</b><br>{d.detail}<br><small>Call-ID: {d.call_id or "—"} | Stream: {d.stream_id or "—"} | confiança: {d.confidence}</small></div>', unsafe_allow_html=True)
        if d.evidence:
            st.json(d.evidence, expanded=False)

with nat_tab:
    if result.nat:
        for f in result.nat:
            st.markdown(f'<div class="sn-{f["severity"]}"><b>{f["title"]}</b><br>{f["detail"]}<br><small>{f["type"]} · origem: {f["source_ip"] or "—"} · Call-ID: {f["call_id"] or "—"}</small></div>', unsafe_allow_html=True)
    else:
        st.success("Nenhum problema de NAT identificado (SIP ALG, rport, SDP privado, mídia de endereço inesperado).")

with ddos_tab:
    if result.ddos:
        st.dataframe(pd.DataFrame([{k: v for k, v in e.items() if k != "top_sources"} for e in result.ddos]), use_container_width=True, hide_index=True)
        for e in result.ddos:
            st.markdown(f'<div class="sn-{e["severity"]}"><b>{e["title"]} → {e["target_ip"]}</b><br>{e["detail"]}</div>', unsafe_allow_html=True)
    else:
        st.success("Nenhum flood ou DDoS identificado (volumétrico, SYN, ICMP, reflexão/amplificação ou flood SIP distribuído).")
    if result.kpis.get("traffic_timeline"):
        st.subheader("Tráfego por segundo (pico)")
        st.line_chart(pd.DataFrame(result.kpis["traffic_timeline"]).set_index("t")[["pps"]])

with sec_tab:
    if result.security:
        st.dataframe(pd.DataFrame(result.security), use_container_width=True, hide_index=True)
    else:
        st.success("Nenhum padrão de ataque SIP identificado (scanner, força bruta, enumeração, flood ou fraude internacional).")

with net_tab:
    if result.kpis.get("icmp_errors"):
        st.subheader("Erros ICMP (destino inalcançável)")
        st.dataframe(pd.DataFrame(result.kpis["icmp_errors"]), use_container_width=True, hide_index=True)
    if result.network_flows:
        st.subheader("Fluxos")
        st.dataframe(pd.DataFrame(result.network_flows[:500]), use_container_width=True, hide_index=True)
        st.caption("Inter-packet gap não é latência. Latência só é exibida quando existe uma medição correlacionável.")

download_cols = st.columns(3)
payload = json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str).encode("utf-8")
download_cols[0].download_button("Baixar JSON", payload, file_name=f"{uploaded.name}.sip-network.json", mime="application/json")
call_csv = pd.DataFrame([{
    "call_id": c.call_id, "from": c.from_uri, "to": c.to_uri, "outcome": c.outcome, "final_status": c.final_status,
    "q850": c.q850_cause, "pdd_ms": c.pdd_ms, "setup_ms": c.setup_time_ms, "duration_s": c.duration_s,
    "disconnect_side": c.disconnect_side, "missing_ack": c.missing_ack, "retransmissions": c.retransmissions,
    "caller_ip": c.caller_ip, "callee_ip": c.callee_ip,
} for c in result.calls]).to_csv(index=False).encode("utf-8")
download_cols[1].download_button("Chamadas CSV", call_csv, file_name=f"{uploaded.name}.calls.csv", mime="text/csv")
rtp_csv = pd.DataFrame([asdict(s) for s in result.rtp_streams]).to_csv(index=False).encode("utf-8")
download_cols[2].download_button("RTP CSV", rtp_csv, file_name=f"{uploaded.name}.rtp.csv", mime="text/csv")
