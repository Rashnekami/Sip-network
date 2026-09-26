"""Grava o laboratório de pcaps de teste (um por anomalia) e o gabarito do que o analisador precisa mostrar.

    python tools/make_lab_pcaps.py pasta_de_saida

Gera pasta_de_saida/<categoria>/<cenario>.pcap e pasta_de_saida/LEIA-ME.md com o que cada captura simula, os códigos
esperados e o resultado atual do motor (acerto ou não).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

from lab import CATEGORIES, SCENARIOS  # noqa: E402
from test_lab import evaluate  # noqa: E402

from sip_network import __version__, analyze_bytes  # noqa: E402

SEV = {"critical": "crítico", "warning": "alerta", "info": "info"}


def main(out: str) -> int:
    lines = [f"# Laboratório de pcaps de teste do Sip-Network {__version__}", "",
             "Cada arquivo simula um problema real de VoIP/WebRTC. Abra no analisador e confira se aparecem os diagnósticos da coluna "
             "**Esperado**. Capturas da categoria *limpo* não podem mostrar nenhum alerta.", "",
             "Todos os pcaps são sintéticos (IPs de exemplo, sem dados de clientes) e gerados por `tools/make_lab_pcaps.py`.", ""]
    total = hits = 0
    for cat, label in CATEGORIES.items():
        items = [s for s in SCENARIOS if s.category == cat]
        if not items:
            continue
        os.makedirs(os.path.join(out, cat), exist_ok=True)
        lines += [f"## {label}", "", "| Arquivo | O que simula | Esperado | Resultado do motor |", "|---|---|---|---|"]
        for s in items:
            data = s.pcap()
            with open(os.path.join(out, cat, s.filename), "wb") as fh:
                fh.write(data)
            r = analyze_bytes(data, s.filename)
            missing, false_alarms, extra = evaluate(s, r)
            ok = not (missing or false_alarms or extra)
            total += 1; hits += ok
            shown = [f"{d.code} ({SEV[d.severity]})" for d in r.diagnostics if d.severity != "info" or d.code in s.expect]
            got = "✅ " + (", ".join(dict.fromkeys(shown)) or "nenhum alerta") if ok else \
                "❌ " + "; ".join(x for x in (f"faltou {missing}" if missing else "", f"alarme falso {false_alarms}" if false_alarms else "",
                                              "; ".join(extra)) if x)
            exp = ", ".join(f"`{c}`" for c in s.expect) or "nenhum alerta"
            lines.append(f"| `{cat}/{s.filename}` | **{s.title}.** {s.what} | {exp} | {got} |")
        lines.append("")
    lines.insert(4, f"**Resultado atual: {hits} de {total} capturas diagnosticadas corretamente.**\n")
    with open(os.path.join(out, "LEIA-ME.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"{total} pcaps em {out} ({hits} corretos)")
    return 0 if hits == total else 1


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
