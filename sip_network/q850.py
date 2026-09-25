from __future__ import annotations

import re

# ITU-T Q.850 cause values most often seen in SIP Reason headers and SIP<->ISDN interworking.
Q850_CAUSES = {
    1: "Número não alocado",
    2: "Sem rota para a rede de trânsito",
    3: "Sem rota para o destino",
    6: "Canal inaceitável",
    16: "Desligamento normal",
    17: "Usuário ocupado",
    18: "Usuário não responde",
    19: "Sem resposta do usuário (alertando)",
    20: "Assinante ausente",
    21: "Chamada rejeitada",
    22: "Número alterado",
    26: "Desligamento de usuário não selecionado",
    27: "Destino fora de serviço",
    28: "Formato de número inválido",
    29: "Facilidade rejeitada",
    31: "Normal, não especificado",
    34: "Nenhum circuito/canal disponível",
    38: "Rede fora de serviço",
    41: "Falha temporária",
    42: "Congestionamento de equipamento de comutação",
    44: "Canal solicitado não disponível",
    47: "Recurso indisponível",
    50: "Facilidade solicitada não contratada",
    55: "Chamadas entrantes barradas no CUG",
    57: "Capacidade do portador não autorizada",
    58: "Capacidade do portador indisponível",
    63: "Serviço ou opção indisponível",
    65: "Capacidade do portador não implementada",
    69: "Facilidade não implementada",
    79: "Serviço ou opção não implementado",
    81: "Referência de chamada inválida",
    87: "Usuário não é membro do CUG",
    88: "Destino incompatível",
    95: "Mensagem inválida",
    96: "Elemento de informação obrigatório ausente",
    97: "Tipo de mensagem inexistente",
    99: "Elemento de informação inexistente",
    100: "Conteúdo de elemento de informação inválido",
    102: "Recuperação por expiração de temporizador",
    111: "Erro de protocolo",
    127: "Interworking, não especificado",
}

# Default Q.850 cause implied by a SIP final response when no Reason header is present (RFC 3398 / RFC 4497 practice).
SIP_TO_Q850 = {
    400: 41, 401: 21, 402: 21, 403: 21, 404: 1, 405: 63, 406: 79, 407: 21, 408: 102, 410: 22,
    413: 127, 414: 127, 415: 79, 416: 127, 420: 127, 421: 127, 423: 127, 480: 18, 481: 41,
    482: 25, 483: 25, 484: 28, 485: 1, 486: 17, 487: 31, 488: 65, 500: 41, 501: 79,
    502: 38, 503: 34, 504: 102, 505: 127, 513: 127, 600: 17, 603: 21, 604: 1, 606: 58,
}


def parse_reason(value: str | None) -> tuple[int | None, str | None]:
    """Return (Q.850 cause, text) from a SIP Reason header value."""
    if not value:
        return None, None
    for part in value.split(","):
        if "q.850" not in part.lower():
            continue
        m = re.search(r"cause\s*=\s*(\d+)", part, re.I)
        t = re.search(r'text\s*=\s*"([^"]*)"', part, re.I)
        if m:
            return int(m.group(1)), (t.group(1) if t else None)
    return None, None


def cause_text(cause: int | None) -> str | None:
    if cause is None:
        return None
    return Q850_CAUSES.get(cause, f"Causa Q.850 {cause}")
