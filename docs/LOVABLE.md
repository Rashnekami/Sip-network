# Ligando o webcheck (Lovable) na API

Pré-requisito: a API publicada (veja [DEPLOY.md](DEPLOY.md)) com a URL e o token em mãos.

## 1. Segredos no Supabase

No painel do Supabase do projeto: **Edge Functions → Secrets** (ou peça ao Lovable), crie:

- `SIP_NETWORK_API_URL` = `https://SEU-DOMINIO` (sem barra no final)
- `SIP_NETWORK_API_TOKEN` = o token da API

## 2. Prompt atual: módulo ao lado do post-it na tela de login (teste público)

Usa a Edge Function pública (sem login, 30 MB, 10 análises por hora por IP) e os campos da versão 2.2 (`nat`, `ddos`, `kpis.charts`).

> Ajuste o Analisador SIP (PCAP) que criamos. Três mudanças: posição, visual e novas seções.
>
> **1. Posição (mais importante)**
> - A rota inicial `/` volta a ser a tela de login do CheckTecnico, exatamente como era antes. O analisador não pode abrir antes do login nem substituir a página inicial. Remova-o da rota inicial.
> - Na tela de login, coloque um cartão "Analisador SIP (PCAP)" ao lado do post-it, com o mesmo tamanho, sombra e cantos do post-it, lado a lado no desktop e empilhado abaixo dele no celular. Não mexa no formulário de login nem no post-it.
> - O cartão mostra: ícone (lucide `Activity`), título "Analisador SIP", subtítulo "Envie um .pcap e veja chamadas, áudio, NAT e ataques", uma área de arrastar e soltar e a nota "Grátis para teste · até 30 MB · 10 análises por hora".
> - O uso continua público, sem login. Ao soltar o arquivo, o cartão mostra o progresso ("Enviando…", "Analisando chamadas…", "Montando relatório…"). Quando a resposta chega, os resultados abrem num painel grande (Dialog em tela cheia no celular e com 90% da largura no desktop) por cima da tela de login. Ao fechar o painel, o usuário volta ao login.
> - Continue usando a Edge Function `analisar-pcap` que já existe, sem mudar as proteções: limite de 30 MB, 10 análises por hora por IP e o token só dentro da Edge Function, nunca no navegador.
>
> **2. Visual**
> - Siga as cores, a fonte e os componentes (shadcn) do CheckTecnico, funcionando no tema claro e no escuro. Use cantos `rounded-2xl`, sombras suaves, bastante espaço e ícones lucide.
> - Use as mesmas cores de severidade em todo o painel: critical = vermelho (`#ef4444`), warning = âmbar (`#f59e0b`) e info = azul (`#3b82f6`). OK = verde (`#22c55e`).
> - No topo do painel: nome do arquivo, duração da captura (`capture.duration_s`), pacotes, botão "Baixar JSON" e botão "Nova análise".
> - Mostre uma faixa de KPIs em cartões com ícone e valor grande:
>   - Chamadas: `kpis.calls.attempts`.
>   - ASR %: verde ≥ 50, âmbar entre 30 e 50, vermelho abaixo de 30.
>   - NER %.
>   - PDD médio: `kpis.calls.pdd_avg_ms` em segundos.
>   - ACD: `kpis.calls.acd_s`.
>   - MOS médio: `kpis.media.mos_avg`, verde ≥ 4, âmbar ≥ 3,6, vermelho abaixo disso.
>   - Críticos: quantidade de `diagnostics` com severity critical.
> - Enquanto analisa, mostre skeletons. Se uma seção não tiver nada, mostre um estado vazio positivo, com check verde e "Nenhum problema de NAT encontrado", em vez de tabela vazia.
> - As tabelas têm cabeçalho fixo, linhas zebradas, busca e badges coloridos por severidade e por desfecho.
>
> **3. Gráficos redondos (rosca)**
> A API já entrega as séries prontas em `kpis.charts`. Cada série é uma lista de `{key, label, value}`. Use `recharts` (PieChart com `innerRadius`, ou seja, rosca), com o total no centro, legenda embaixo e tooltip com valor e %. Se a série estiver vazia, esconda o gráfico. Crie um componente `DonutChart` reutilizável.
> - Aba **Visão geral**:
>   - Grade de roscas com "Achados por severidade" (`diagnostics_by_severity`, cores de severidade pelo `key`).
>   - "Problemas por área" (`problems_by_category`).
>   - "Desfecho das chamadas" (`call_outcomes`: answered verde, busy/no_answer/cancelled cinza, o resto vermelho).
>   - "Códigos de erro SIP" (`sip_error_codes`).
>   - "Qualidade de voz (MOS)" (`mos_bands`: otimo verde, bom verde-claro, regular âmbar, ruim vermelho).
>   - Abaixo, os 5 achados mais graves.
> - Aba **NAT**: rosca `nat_by_type`.
> - Aba **DDoS / Flood**: rosca `ddos_by_type` e um gráfico de linha (recharts LineChart) com `kpis.traffic_timeline`: eixo X é `t`, com segundos Unix formatados como hora; eixo Y é `pps`. Pinte de vermelho as faixas de tempo de cada evento de `ddos` (`start` a `end`) com ReferenceArea.
> - Aba **Segurança**: rosca `security_by_type`.
>
> **4. Abas do painel**
> - Visão geral.
> - Achados: `diagnostics`, com filtro por severidade e por área (`category`: sinalizacao=Sinalização, midia=Mídia/áudio, nat=NAT, seguranca=Segurança, ddos=DDoS/flood, rede=Rede/QoS, registro=Registro). Cada achado vira um cartão com borda colorida, `title`, `detail`, `code` e `call_id`, e um "ver evidências" que expande o `evidence` em JSON formatado.
> - Chamadas: a tabela como já está. Ao clicar, abre o `ladder_svg` num container com scroll horizontal, os achados da chamada e os `media_endpoints`.
> - Qualidade de áudio: `rtp_streams`, com MOS < 3,6 em âmbar e < 3,1 em vermelho.
> - **NAT (novo)**: lista de `nat` em cartões por severidade, com `title`, `detail`, `source_ip`, `call_id` e evidências. No topo, uma explicação curta: "NAT e SIP ALG são a causa nº 1 de áudio mudo, unidirecional e queda de chamadas".
> - **DDoS / Flood (novo)**: os gráficos acima e uma tabela de `ddos` com `title`, `target_ip`:`target_port`, `duration_s`, `peak_pps`, `peak_mbps`, `sources` e `severity`. Ao clicar num evento, mostre `detail` e a lista `top_sources` (ip e pacotes).
> - Segurança (`security`), Registros (`registrations`) e Rede (`kpis.icmp_errors`).
>
> Traduza os `type` de NAT e DDoS usando o `title` que já vem em cada item. Não invente textos.

## 2b. Prompt antigo: página interna com login

> Crie uma nova página "Análise SIP (PCAP)" no menu de ferramentas.
>
> **Backend:** crie uma Supabase Edge Function chamada `analisar-pcap` que:
> - exige usuário autenticado (verifique o JWT do Supabase);
> - recebe `multipart/form-data` com o campo `file` (.pcap/.pcapng, até 100 MB) e, opcionalmente, `thresholds` (texto JSON);
> - repassa o mesmo formulário via `fetch` para `${SIP_NETWORK_API_URL}/v1/analyze` com o header `Authorization: Bearer ${SIP_NETWORK_API_TOKEN}` (ambos lidos de `Deno.env`);
> - devolve o JSON da resposta e o mesmo status HTTP. Mensagens de erro: 413 "arquivo grande demais", 422 "arquivo não é uma captura válida", 429 "servidor ocupado, tente de novo".
> - Nunca exponha o token ao navegador.
>
> **Frontend:** a página tem uma área de upload (arrastar e soltar) que chama a Edge Function e mostra um indicador de progresso enquanto analisa. Com a resposta JSON, mostre:
> 1. **Cartões de KPI** no topo: `kpis.calls.attempts` (Chamadas), `asr_pct` (ASR %), `ner_pct` (NER %), `pdd_avg_ms` (PDD médio), `acd_s` (ACD), `kpis.media.mos_avg` (MOS médio) e a quantidade de `diagnostics` com `severity == "critical"`.
> 2. **Achados**: lista de `diagnostics` ordenada como veio, com cor por `severity` (critical vermelho, warning amarelo, info azul), mostrando `title`, `detail`, `code` e `call_id`. Filtro por severidade.
> 3. **Chamadas**: tabela de `calls` com `call_id`, `from_uri`, `to_uri`, `outcome`, `final_status`, `q850_cause`, `pdd_ms`, `duration_s`, `disconnect_side`, `negotiated_codecs`, `missing_ack`. Filtro "somente com problema" (chamadas que aparecem em diagnostics com severity critical/warning). Ao clicar numa chamada, abra um painel com o `ladder_svg` renderizado (é um SVG pronto, insira com `dangerouslySetInnerHTML` dentro de um container com scroll horizontal), os achados daquela chamada e os `media_endpoints`.
> 4. **Qualidade de áudio**: tabela de `rtp_streams` com `call_id`, `src_ip`:`src_port` → `dst_ip`:`dst_port`, `codec`, `loss_percent`, `jitter_ms`, `mos`, `rtcp_remote_loss_pct`, `dscp`, `dtmf_digits`. Pinte MOS < 3.6 de amarelo e < 3.1 de vermelho.
> 5. **Registros** (`registrations`) e **Segurança** (`security`) em abas próprias.
> 6. Botão "Baixar JSON" com a resposta completa.
>
> Traduza os valores de `outcome`: answered=atendida, busy=ocupado, no_answer=não atendida, cancelled=cancelada, rejected=recusada, not_found=número inexistente, auth_failed=falha de autenticação, media_negotiation_failed=codec incompatível, server_error=erro do servidor, timeout=timeout, no_response=sem resposta.
>
> Opcional: salve cada análise numa tabela `pcap_analyses` (id, user_id, filename, created_at, kpis jsonb, diagnostics jsonb) com RLS por usuário, e mostre o histórico na página.

## 3. Código de referência da Edge Function

Se o Lovable gerar algo diferente, este é o comportamento esperado:

```ts
// supabase/functions/analisar-pcap/index.ts
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
    global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
  });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response(JSON.stringify({ detail: "Não autenticado" }), { status: 401, headers: cors });

  const form = await req.formData();
  const upstream = await fetch(`${Deno.env.get("SIP_NETWORK_API_URL")}/v1/analyze`, {
    method: "POST",
    headers: { Authorization: `Bearer ${Deno.env.get("SIP_NETWORK_API_TOKEN")}` },
    body: form,
  });
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
});
```

Observação: as Edge Functions do Supabase têm limite de tamanho de requisição e de tempo de execução (veja os valores atuais do seu plano). Se os pcaps passarem desse limite, o caminho é o navegador enviar o arquivo para o **Supabase Storage** e a Edge Function mandar para a API só a URL assinada. Dá para adicionar um endpoint `/v1/analyze-url` na API quando for necessário.
