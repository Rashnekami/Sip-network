# Publicando a API (para o webcheck/checktecnico)

O webcheck (Lovable + Supabase) não roda Python. A análise fica numa API separada (`api.py` + `Dockerfile.api`), e o Supabase conversa com ela.

```
Técnico → webcheck (React/Lovable) → Supabase Edge Function "analisar-pcap" → Sip-Network API → JSON
```

O token da API fica guardado **só** na Edge Function. Ele nunca vai para o navegador.

## Quanto de máquina precisa

Medido: um pcap de 27 MB (120 mil pacotes, 60 chamadas) leva ~4 s e usa ~180 MB de RAM. Conte com **~7× o tamanho do arquivo em RAM** por análise simultânea.

| Maior pcap esperado | RAM recomendada |
|---|---|
| até 50 MB | 1 GB |
| até 100 MB (padrão da API) | 2 GB |
| até 250 MB | 4 GB e `SIP_NETWORK_MAX_CONCURRENT=1` |

## Variáveis de ambiente

| Variável | Para quê |
|---|---|
| `SIP_NETWORK_API_TOKEN` | **obrigatória**. Gere uma senha longa: `openssl rand -hex 32` |
| `SIP_NETWORK_MAX_UPLOAD_MB` | limite do arquivo (padrão 100) |
| `SIP_NETWORK_MAX_CONCURRENT` | análises ao mesmo tempo (padrão 2) |
| `SIP_NETWORK_CORS_ORIGINS` | só se o navegador for chamar a API direto (não recomendado) |

## Opção A: Railway (mais simples, recomendada)

1. Crie conta em railway.com e conecte o GitHub.
2. **New Project → Deploy from GitHub repo → Rashnekami/Sip-network**.
3. O arquivo `railway.toml` do repositório já manda o Railway usar o `Dockerfile.api` e checar `/health`. Não precisa mexer no build.
4. Em **Variables**, adicione `SIP_NETWORK_API_TOKEN`.
5. Em **Settings → Networking**, clique em **Generate Domain**. Você recebe algo como `https://sip-network-production.up.railway.app`.
6. Teste: abra `https://SEU-DOMINIO/health`. Deve responder `{"status":"ok",...}`.

Cada push na branch principal publica de novo sozinho. O plano Hobby custa US$ 5/mês e inclui US$ 5 de uso. A cobrança é pelo que a API usa de fato: parada ela ocupa poucas dezenas de MB, então o uso normal fica dentro dos US$ 5. Em **Workspace → Usage** dá para definir um limite de gasto.

## Opção B: Render

1. render.com → **New → Web Service** → conecte o repositório.
2. Runtime **Docker**, Dockerfile path `Dockerfile.api`.
3. Em **Environment**, adicione `SIP_NETWORK_API_TOKEN`.
4. Escolha um plano com pelo menos 1–2 GB de RAM. O plano gratuito dorme depois de alguns minutos parado (a primeira análise demora ~1 min) e tem pouca memória.

## Opção C: VPS Ubuntu (mais barato por GB de RAM, mas você cuida do servidor)

Qualquer VPS com Ubuntu 22.04/24.04 (Hetzner, Contabo, DigitalOcean, Magalu Cloud…) e um domínio apontando para o IP.

```bash
# 1. Docker
curl -fsSL https://get.docker.com | sh

# 2. Código e imagem
git clone https://github.com/Rashnekami/Sip-network.git && cd Sip-network
docker build -f Dockerfile.api -t sip-network-api .
docker run -d --name sip-network-api --restart unless-stopped \
  -e SIP_NETWORK_API_TOKEN="$(openssl rand -hex 32)" \
  -p 127.0.0.1:8000:8000 sip-network-api
docker exec sip-network-api env | grep SIP_NETWORK_API_TOKEN   # anote o token

# 3. HTTPS automático com Caddy
sudo apt install -y caddy
echo 'api.seudominio.com.br {
  request_body { max_size 110MB }
  reverse_proxy 127.0.0.1:8000
}' | sudo tee /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Para atualizar: `git pull && docker build -f Dockerfile.api -t sip-network-api . && docker rm -f sip-network-api` e rode o `docker run` de novo com o mesmo token. Mantenha o Ubuntu atualizado (`sudo apt upgrade`) e o firewall liberando só 22, 80 e 443.

## Contrato da API

`GET /health` → `{"status": "ok", "version": "2.1.0"}`

`POST /v1/analyze` (multipart/form-data), header `Authorization: Bearer <token>`:

| Campo | Tipo | Padrão |
|---|---|---|
| `file` | arquivo .pcap/.pcapng | obrigatório |
| `thresholds` | JSON com campos de `Thresholds` (ex.: `{"pdd_warning_ms": 4000}`) | padrões |
| `include_messages` | `true`/`false`: headers e corpo SIP completos | `false` |
| `include_ladder` | `true`/`false`: `ladder_svg` em cada chamada | `true` |

Resposta: o JSON descrito em [INTEGRACAO.md](INTEGRACAO.md). Erros: `401` token, `413` arquivo grande, `422` arquivo inválido, `429` servidor ocupado (tente de novo), `503` token não configurado.

```bash
curl -H "Authorization: Bearer $TOKEN" -F file=@captura.pcap https://SEU-DOMINIO/v1/analyze
```
