from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import analyze_bytes

SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


def _summary(result) -> str:
    k = result.kpis.get("calls", {})
    m = result.kpis.get("media", {})
    lines = [
        f"Captura: {result.capture['filename']}  pacotes={result.capture['packets']}  duração={result.capture['duration_s']:.1f}s",
        f"Chamadas={k.get('attempts', 0)}  atendidas={k.get('answered', 0)}  ASR={k.get('asr_pct')}%  NER={k.get('ner_pct')}%  "
        f"PDD médio={k.get('pdd_avg_ms')} ms  ACD={k.get('acd_s')} s",
        f"RTP fluxos={m.get('streams', 0)}  MOS médio={m.get('mos_avg')}  MOS mín={m.get('mos_min')}",
        f"Desfechos: {k.get('outcomes', {})}",
        "",
        "Achados:",
    ]
    for d in result.diagnostics:
        ref = f" [{d.call_id}]" if d.call_id else ""
        lines.append(f"  {d.severity.upper():8} {d.code}{ref}: {d.detail}")
    if not result.diagnostics:
        lines.append("  nenhum")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sip-Network - analisador PCAP/PCAPNG SIP/RTP")
    parser.add_argument("capture", type=Path)
    parser.add_argument("--json", dest="json_path", type=Path, help="salvar relatório JSON")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--summary", action="store_true", help="resumo legível em texto em vez de JSON")
    parser.add_argument("--no-messages", action="store_true", help="omitir cabeçalhos/corpo SIP completos do JSON")
    parser.add_argument("--fail-on", choices=["warning", "critical"],
                        help="código de saída 2 se houver achado com esta severidade ou maior (para automação)")
    args = parser.parse_args()
    result = analyze_bytes(args.capture.read_bytes(), args.capture.name)
    try:
        if args.summary:
            print(_summary(result))
        else:
            payload = result.to_dict(include_messages=not args.no_messages)
            text = json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None, default=str)
            if args.json_path:
                args.json_path.write_text(text, encoding="utf-8")
                print(f"Relatório salvo em {args.json_path}")
            else:
                print(text)
    except BrokenPipeError:
        sys.stderr.close()
    if args.fail_on:
        limit = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK.get(d.severity, 0) >= limit for d in result.diagnostics):
            sys.exit(2)


if __name__ == "__main__":
    main()
