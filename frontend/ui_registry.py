"""Metadados de interface para as alternativas de autenticação.

Esta registry permite que o frontend mostre opções amigáveis ao utilizador
sem acoplar a interface aos detalhes de cada implementação.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class AlternativaUI:
    codigo: str
    titulo: str
    descricao: str
    icone: str = "🔐"


_ALTERNATIVAS_UI: Dict[str, AlternativaUI] = {
    "alt1": AlternativaUI(
        codigo="alt1",
        titulo="Alternativa 1",
        descricao="Reconhecimento facial baseado na base de pessoas permitidas.",
        icone="👤",
    ),
    "alt2": AlternativaUI(
        codigo="alt2",
        titulo="Alternativa 2",
        descricao="Modelo FaceCNN afinado (best_cnn_model).",
        icone="🧠",
    ),
    "alt3": AlternativaUI(
        codigo="alt3",
        titulo="Alternativa 3",
        descricao="Modelo ResNet50 afinado (best_resnet_model).",
        icone="🚀",
    ),
}


def listar_alternativas_ui() -> list[AlternativaUI]:
    """Devolve as alternativas disponíveis para exibição no frontend."""
    return [
        _ALTERNATIVAS_UI[codigo]
        for codigo in sorted(_ALTERNATIVAS_UI.keys())
    ]


def obter_alternativa_ui(codigo: str) -> AlternativaUI:
    """Devolve os metadados de uma alternativa específica."""
    try:
        return _ALTERNATIVAS_UI[codigo.lower()]
    except KeyError as exc:
        raise ValueError(f"Alternativa de UI desconhecida: {codigo}") from exc


__all__ = ["AlternativaUI", "listar_alternativas_ui", "obter_alternativa_ui"]

