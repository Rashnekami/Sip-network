"""
Streamlit Application
====================

This module exposes a Streamlit application that allows users to upload
packet capture files and interactively explore basic network and VoIP
statistics.  The user interface is deliberately simple: after uploading
a PCAP file the app parses the data using :func:`voip_analyzer.parser`
and displays two tables – one for general network metrics and another for
VoIP‑specific flows.  Filters can be applied by IP address or protocol to
focus on specific conversations.

To run the application locally install the required Python packages
(`streamlit` and `pandas`) and execute:

    streamlit run voip_analyzer/app.py

This file does not import any heavy dependencies until after the user has
uploaded data, so that the initial import cost is low.  If Streamlit is
not available in the environment the module will still import but running
the UI will fail; see the project README for installation instructions.
"""

from __future__ import annotations

import json
import tempfile
from typing import List, Optional

import pandas as pd
import streamlit as st

from .parser import read_pcap, read_pcap_bytes, Packet
from .analysis import (
    analyze_network,
    analyze_voip,
    analyze_sip_calls,
    analyze_rtp_streams,
    detect_floods,
    search_payload,
    detect_port_scans,
    audit_firewall,
)


def _filter_dataframe(df: pd.DataFrame, ip_filter: str, protocol_filter: str) -> pd.DataFrame:
    """Filter a pandas DataFrame based on IP and protocol criteria.

    Args:
        df: The input DataFrame.
        ip_filter: An IP address substring to filter source or destination IP.
        protocol_filter: Protocol name to filter (e.g. "TCP", "UDP", "ICMP", "SIP", "RTP", "ALL").

    Returns:
        A filtered DataFrame.
    """
    result = df
    if ip_filter:
        # Case insensitive partial match on source or destination
        mask = result["source_ip"].str.contains(ip_filter, case=False, na=False) | result["dest_ip"].str.contains(ip_filter, case=False, na=False)
        result = result[mask]
    if protocol_filter and protocol_filter.upper() != "ALL":
        result = result[result["protocol"].str.upper() == protocol_filter.upper()]
    return result


def main() -> None:
    st.set_page_config(page_title="VoIP & Network PCAP Analyzer", page_icon="📡", layout="wide")
    st.title("VoIP & Network PCAP Analyzer")
    st.markdown(
        "Upload a PCAP file to compute basic network and VoIP metrics. "
        "This tool parses IPv4/TCP/UDP packets without external dependencies, "
        "and provides simple latency, jitter and MOS calculations."
    )

    uploaded_file = st.file_uploader("Selecione um arquivo PCAP", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        # Read bytes from Streamlit's uploader
        data = uploaded_file.read()
        with st.spinner("Analisando PCAP..."):
            packets: List[Packet] = read_pcap_bytes(data)
        st.success(f"{len(packets)} pacotes carregados e analisados.")

        # Network analysis
        network_metrics = analyze_network(packets)
        df_net = pd.DataFrame(network_metrics)

        # VoIP analysis
        voip_metrics = analyze_voip(packets)
        df_voip = pd.DataFrame(voip_metrics)

        # Advanced SIP/RTP analysis
        sip_calls = analyze_sip_calls(packets)
        df_calls = pd.DataFrame(sip_calls)
        rtp_quality = analyze_rtp_streams(packets)
        df_rtp = pd.DataFrame(rtp_quality)
        # Flood detection (default threshold 500)
        flood_threshold = st.sidebar.number_input(
            "Limite de pacotes/s para detectar flood", min_value=100, max_value=10000, value=500, step=100
        )
        flood_events = detect_floods(packets, threshold=flood_threshold)
        # Port scan detection parameters
        st.sidebar.subheader("Configuração de Detecção de Scans")
        port_thr = st.sidebar.number_input(
            "Portas únicas para alertar scan vertical", min_value=10, max_value=1000, value=50, step=10
        )
        ip_thr = st.sidebar.number_input(
            "Hosts únicos para alertar scan horizontal", min_value=10, max_value=1000, value=50, step=10
        )
        time_window = st.sidebar.number_input(
            "Janela de tempo (ms) para contagem de scans (0 = todo arquivo)",
            min_value=0, max_value=300000, value=60000, step=10000
        )
        scan_events = detect_port_scans(packets, port_threshold=port_thr, ip_threshold=ip_thr, time_window_ms=time_window)
        df_scans = pd.DataFrame(scan_events)
        # Firewall audit
        fw_results = audit_firewall(packets)
        df_fw = pd.DataFrame(fw_results)
        df_floods = pd.DataFrame(flood_events)

        # Filtering UI
        st.sidebar.header("Filtros")
        ip_filter = st.sidebar.text_input("Filtrar por IP (origem ou destino)")
        protocol_options_net = ["ALL"] + sorted(df_net["protocol"].dropna().unique().tolist())
        protocol_filter_net = st.sidebar.selectbox("Protocolo (Análise de Rede)", protocol_options_net)
        protocol_options_voip = ["ALL"] + sorted(df_voip["protocol"].dropna().unique().tolist())
        protocol_filter_voip = st.sidebar.selectbox("Protocolo (Análise de VoIP)", protocol_options_voip)

        # Display network metrics table
        st.header("Análise de Rede")
        st.caption("Métricas agregadas por fluxo (IP de origem → IP de destino e protocolo).")
        filtered_net = _filter_dataframe(df_net, ip_filter, protocol_filter_net)
        st.dataframe(filtered_net, use_container_width=True)

        # Display VoIP metrics table
        st.header("Análise de VoIP")
        st.caption("Fluxos SIP/RTP e métricas de chamada.")
        filtered_voip = _filter_dataframe(df_voip, ip_filter, protocol_filter_voip)
        st.dataframe(filtered_voip, use_container_width=True)

        # SIP call summary
        st.header("Resumo de Chamadas SIP")
        st.caption("Reconstituição de chamadas SIP baseada em Call-ID e verificação de mensagens faltantes.")
        if df_calls.empty:
            st.write("Nenhuma chamada SIP identificada.")
        else:
            st.dataframe(df_calls, use_container_width=True)

        # RTP quality analysis
        st.header("Qualidade de RTP")
        st.caption("Estatísticas de jitter e perda de pacotes por fluxo RTP (portas 10000–20000).")
        if df_rtp.empty:
            st.write("Nenhum fluxo RTP identificado.")
        else:
            st.dataframe(df_rtp, use_container_width=True)

        # Flood detection
        st.header("Detecção de Floods/Storms")
        st.caption("Eventos em que a taxa de pacotes por segundo excedeu o limite configurado.")
        if df_floods.empty:
            st.write("Nenhum flood detectado com o limite atual.")
        else:
            st.dataframe(df_floods, use_container_width=True)

        # Port scan detection
        st.header("Detecção de Varreduras de Porta/Host")
        st.caption(
            "Heurística simples baseada no número de portas/hosts únicos contatados por cada origem dentro de uma janela de tempo."
        )
        if df_scans.empty:
            st.write("Nenhum scan detectado com os parâmetros atuais.")
        else:
            st.dataframe(df_scans, use_container_width=True)

        # Firewall audit
        st.header("Auditoria de Firewall (Conexões Possivelmente Bloqueadas)")
        st.caption(
            "Sinaliza fluxos com muito poucos pacotes (≤3) que podem indicar portas bloqueadas ou resetadas."
        )
        if df_fw.empty:
            st.write("Nenhuma possível porta bloqueada identificada.")
        else:
            st.dataframe(df_fw, use_container_width=True)

        # Payload search
        st.header("Busca em Payloads")
        search_term = st.text_input("Digite uma string para procurar nos payloads", value="")
        if search_term:
            search_results = search_payload(packets, search_term)
            df_search = pd.DataFrame(search_results)
            if df_search.empty:
                st.write("Nenhum pacote contém a string especificada.")
            else:
                st.dataframe(df_search, use_container_width=True)

        # Prepare JSON report for download
        report = {
            "network_metrics": network_metrics,
            "voip_metrics": voip_metrics,
            "sip_calls": sip_calls,
            "rtp_quality": rtp_quality,
            "flood_events": flood_events,
            "scan_events": scan_events,
            "firewall_audit": fw_results,
        }
        json_report = json.dumps(report, indent=2, ensure_ascii=False)

        st.download_button(
            "Baixar relatório JSON",
            data=json_report,
            file_name="pcap_analysis_report.json",
            mime="application/json",
        )

    st.info(
        "Esta ferramenta é experimental e usa heurísticas simples. Para análises "
        "mais aprofundadas (extração de mensagens SIP, detecção de falhas de "
        "firewall, testes de segurança), consulte projetos como sippts e libpcap "
        "ou integre ferramentas externas."
    )


if __name__ == "__main__":
    main()
