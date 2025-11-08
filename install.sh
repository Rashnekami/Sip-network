#!/bin/bash

# --- Script de Instalação e Execução do VoIP Analyzer ---

# 1. Instalar dependências do sistema (para garantir que o venv funcione)
echo "1. Instalando dependências do sistema..."
sudo apt update
sudo apt install -y python3-venv

# 2. Criar e ativar o ambiente virtual
echo "2. Criando e ativando o ambiente virtual..."
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependências Python
echo "3. Instalando dependências Python (Streamlit, Pandas, etc.)..."
pip install -r voip_analyzer/requirements.txt

# 4. Corrigir o problema de importação (garantir que o diretório pai seja reconhecido)
# Isso é necessário para que as importações absolutas funcionem corretamente
export PYTHONPATH=$PYTHONPATH:$(pwd)

# 5. Executar a aplicação Streamlit em segundo plano
echo "4. Iniciando a aplicação Streamlit em segundo plano na porta 8501..."
# Usamos nohup para que a aplicação continue rodando mesmo após o logout
# O Streamlit é executado com --server.address 0.0.0.0 para ser acessível externamente
nohup streamlit run voip_analyzer/app.py --server.port 8501 --server.address 0.0.0.0 > streamlit.log 2>&1 &

# 6. Exibir status e instruções
echo "----------------------------------------------------------------"
echo "INSTALAÇÃO CONCLUÍDA!"
echo "A aplicação VoIP Analyzer está rodando em segundo plano."
echo "Para verificar o log de execução, use: tail -f streamlit.log"
echo ""
echo "ACESSO LOCAL:"
echo "Acesse a aplicação no seu navegador na porta 8501."
echo "Se estiver no servidor, use: http://localhost:8501"
echo "Se estiver em outra máquina na mesma rede, use: http://[IP_DO_SEU_SERVIDOR]:8501"
echo ""
echo "PRÓXIMO PASSO (NGROK):"
echo "Para expor a aplicação publicamente (e.g., para ngrok), a porta a ser exposta é a 8501."
echo "Exemplo de comando ngrok (após a instalação):"
echo "ngrok http 8501"
echo "----------------------------------------------------------------"

# 7. Desativar o ambiente virtual (opcional, mas boa prática)
deactivate

exit 0
