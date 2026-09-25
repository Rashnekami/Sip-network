# Ligando o webcheck (Lovable) na API

Pré-requisito: a API publicada (veja [DEPLOY.md](DEPLOY.md)) com a URL e o token em mãos.

## 1. Segredos no Supabase

No painel do Supabase do projeto: **Edge Functions → Secrets** (ou peça ao Lovable), crie:

- `SIP_NETWORK_API_URL` = `https://SEU-DOMINIO` (sem barra no final)
- `SIP_NETWORK_API_TOKEN` = o token da API

## 2. Prompt para colar no Lovable

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
