from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import analyze_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description="Sip-Network 2.0 - analisador PCAP/PCAPNG SIP/RTP")
    parser.add_argument("capture", type=Path)
    parser.add_argument("--json", dest="json_path", type=Path, help="salvar relatório JSON")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = analyze_bytes(args.capture.read_bytes(), args.capture.name)
    payload = result.to_dict()
    text = json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None, default=str)
    if args.json_path:
        args.json_path.write_text(text, encoding="utf-8")
        print(f"Relatório salvo em {args.json_path}")
    else:
        print(text)

if __name__ == "__main__":
    main()
