# VoIP & Network PCAP Analyzer

Este projeto é uma implementação em Python/Streamlit de um analisador de capturas de pacotes (PCAP) com foco em tráfego de rede geral, VoIP (SIP/RTP) e diagnósticos de segurança. Ele foi inspirado em diversas ferramentas de análise existentes e unifica estatísticas básicas de fluxo, reconstrução de chamadas SIP, análise de qualidade de mídia, detecção de floods/storms, busca em payloads e auditorias simples de firewall.

## Principais funcionalidades

- **Upload e parsing de arquivos `.pcap`/`.pcapng`** diretamente pela interface web.
- **Análise de rede:** estatísticas agregadas por fluxo (IP origem/destino e protocolo), média/mínima/máxima latência e jitter, contagem de pacotes e bytes, detecção simples de storms (broadcast/multicast/ARP/DHCP) e possíveis erros de NAT.
- **Análise VoIP:** identificação de fluxos SIP/RTP, cálculo de jitter, estimativa de MOS, reconstrução de chamadas SIP com verificação de mensagens faltantes (ACK/BYE) e análise de qualidade de RTP (jitter e perda de pacotes). 
- **Detecção de floods e storms:** identifica picos de tráfego por IP/protocolo que excedam um limite configurável (ex.: 500 pacotes/s).
- **Detecção de port scans:** aponta varreduras verticais (muitas portas em um host) e horizontais (mesma porta em muitos hosts) a partir de um único IP de origem.
- **Auditoria de firewall:** sinaliza fluxos com muito poucos pacotes (1–3) que podem indicar portas bloqueadas ou resets.
- **Busca em payloads:** permite pesquisar strings em cargas de pacotes (útil para encontrar IOCs, senhas em texto claro, etc.).
- **Exportação de relatório JSON** com todas as métricas calculadas.

## Requisitos

- **Sistema operacional:** Qualquer distribuição Linux com Python 3.8 ou superior. Testado no Ubuntu 22.04.
- **Python:** Versão 3.8+ com `pip` instalado.
- **Dependências Python:** `streamlit` e `pandas`. Estão listadas em `requirements.txt`.

## Instalação e execução (Ubuntu)

1. **Atualize o sistema e instale Python:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip -y
   ```

2. **Clone ou extraia este projeto** em um diretório de sua preferência. O código está dentro da pasta `voip_analyzer`.

3. **Instale as dependências:**
   ```bash
   pip install -r voip_analyzer/requirements.txt
   # ou instale manualmente
   pip install streamlit pandas
   ```

4. **Execute a aplicação Streamlit:**
   ```bash
   cd voip_analyzer
   streamlit run app.py
   ```
   Por padrão, o Streamlit escuta na porta `8501`. A interface será acessível via `http://localhost:8501`.

5. **(Opcional) Tornar acessível via internet usando ngrok:**
   - Crie uma conta no [ngrok.com](https://ngrok.com/) e obtenha seu *token* de autenticação.
   - Instale o ngrok:
     ```bash
     wget https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-linux-amd64.zip
     unzip ngrok-stable-linux-amd64.zip
     sudo mv ngrok /usr/local/bin/
     ```
   - Autentique seu cliente ngrok (substitua `<token>` pelo seu token real):
     ```bash
     ngrok config add-authtoken <token>
     ```
   - Inicie um túnel para a porta do Streamlit (8501):
     ```bash
     ngrok http 8501
     ```
   - O terminal exibirá uma URL pública (ex.: `https://1234.ngrok.io`). Compartilhe este link com os colaboradores da sua empresa para acessar o dashboard.

## Uso básico

1. Abra a interface web (local ou via ngrok).
2. Clique em **“Selecione um arquivo PCAP”** e carregue seu arquivo `.pcap` ou `.pcapng` (até dezenas de megabytes). A análise começará automaticamente.
3. Use os filtros na barra lateral para restringir por IP ou protocolo. Ajuste os limites de detecção de floods e scans conforme necessário.
4. Navegue entre as seções para visualizar:
   - **Análise de Rede**
   - **Análise de VoIP**
   - **Resumo de Chamadas SIP**
   - **Qualidade de RTP**
   - **Detecção de Floods/Storms**
   - **Detecção de Varreduras de Porta/Host**
   - **Auditoria de Firewall**
   - **Busca em Payloads**
5. Clique em **“Baixar relatório JSON”** para salvar um arquivo com todos os dados e métricas.

## Observações

* O parser embutido suporta apenas IPv4 e protocolos Ethernet básicos (TCP/UDP/ICMP/ARP). Pacotes IPv6, VLAN e outros são ignorados.
* As heurísticas usadas para detectar floods, scans e firewall blocks são simplificadas e podem gerar falsos positivos ou negativos. Ajuste os limites de forma conservadora conforme o ambiente.
* Para análises forenses profundas (extração de arquivos, decodificação de codecs variados, suporte a IPv6), recomenda‑se integrar bibliotecas adicionais (como Scapy ou PyShark) ou estender os módulos em `analysis.py`.

## Licença

Este projeto foi desenvolvido como prova de conceito, unificando várias ideias de repositórios de código aberto (PCAP‑Analyzer, SIP‑Analyzer‑MVP, VoIP‑Analyzer, pcapSearch, sippts). Use‑o e modifique‑o conforme necessário para fins educacionais e internos.