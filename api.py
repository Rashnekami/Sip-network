"""HTTP API for Sip-Network: lets web apps (checktecnico/webcheck on Lovable + Supabase) analyse captures.

Run:  uvicorn api:app --host 0.0.0.0 --port 8000

Environment:
  SIP_NETWORK_API_TOKEN       required; clients send "Authorization: Bearer <token>"
  SIP_NETWORK_MAX_UPLOAD_MB   upload limit (default 100)
  SIP_NETWORK_MAX_CONCURRENT  analyses running at the same time (default 2); each uses ~6-7x the file size in RAM
  SIP_NETWORK_CORS_ORIGINS    comma-separated browser origins allowed to call the API directly (default: none)
"""
from __future__ import annotations

import hmac
import json
import os
import threading
from dataclasses import fields

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from sip_network import Thresholds, __version__, analyze_bytes
from sip_network.ladder import ladder_svg

TOKEN = os.getenv("SIP_NETWORK_API_TOKEN", "")
MAX_UPLOAD = int(float(os.getenv("SIP_NETWORK_MAX_UPLOAD_MB", "100")) * 1024 * 1024)
SLOTS = threading.BoundedSemaphore(int(os.getenv("SIP_NETWORK_MAX_CONCURRENT", "2")))
THRESHOLD_FIELDS = {f.name: f.type for f in fields(Thresholds)}

app = FastAPI(title="Sip-Network API", version=__version__)
origins = [o.strip() for o in os.getenv("SIP_NETWORK_CORS_ORIGINS", "").split(",") if o.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"],
                       allow_headers=["Authorization", "Content-Type"])


def _check_token(authorization: str | None) -> None:
    if not TOKEN:
        raise HTTPException(503, "SIP_NETWORK_API_TOKEN não configurado no servidor.")
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied.encode(), TOKEN.encode()):
        raise HTTPException(401, "Token inválido.")


def _thresholds(raw: str | None) -> Thresholds:
    if not raw:
        return Thresholds()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(422, f"thresholds não é JSON válido: {exc}") from exc
    unknown = set(data) - set(THRESHOLD_FIELDS)
    if unknown:
        raise HTTPException(422, f"Campos de thresholds desconhecidos: {sorted(unknown)}")
    if "expected_sip_dscp" in data:
        data["expected_sip_dscp"] = tuple(data["expected_sip_dscp"])
    return Thresholds(**data)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/v1/analyze")
def analyze(
    file: UploadFile = File(..., description="Arquivo .pcap ou .pcapng"),
    thresholds: str | None = Form(None, description="JSON com campos de Thresholds a sobrescrever"),
    include_messages: bool = Form(False, description="incluir cabeçalhos/corpo SIP completos"),
    include_ladder: bool = Form(True, description="incluir o ladder SVG de cada chamada"),
    authorization: str | None = Header(None),
) -> Response:
    _check_token(authorization)
    th = _thresholds(thresholds)
    chunks, size = [], 0
    while chunk := file.file.read(1024 * 1024):
        size += len(chunk)
        if size > MAX_UPLOAD:
            raise HTTPException(413, f"Arquivo acima de {MAX_UPLOAD // (1024 * 1024)} MB. Filtre a captura antes de enviar.")
        chunks.append(chunk)
    if not SLOTS.acquire(blocking=False):
        raise HTTPException(429, "Servidor ocupado com outras análises. Tente novamente em alguns segundos.")
    try:
        result = analyze_bytes(b"".join(chunks), file.filename or "capture", th)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    finally:
        SLOTS.release()
    payload = result.to_dict(include_messages=include_messages)
    if include_ladder:
        svgs = {c.call_id: ladder_svg(c) for c in result.calls}
        for c in payload["calls"]:
            c["ladder_svg"] = svgs.get(c["call_id"])
    return Response(json.dumps(payload, ensure_ascii=False, default=str), media_type="application/json")
