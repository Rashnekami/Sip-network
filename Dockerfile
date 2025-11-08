# Use uma imagem base Python
FROM python:3.11-slim

# Define o diretório de trabalho dentro do contêiner
WORKDIR /app

# Copia o arquivo de requisitos e instala as dependências
COPY voip_analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do código da aplicação
COPY voip_analyzer /app/voip_analyzer

# Define a porta que o Streamlit irá usar
EXPOSE 8501

# Comando para rodar a aplicação Streamlit
# O Streamlit deve ser executado com a opção --server.port 8501 e --server.address 0.0.0.0
CMD ["streamlit", "run", "voip_analyzer/app.py", "--server.port", "8501", "--server.address", "0.0.0.0"]
