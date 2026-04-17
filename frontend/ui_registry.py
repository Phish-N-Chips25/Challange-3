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
        titulo="Alt 1 · Embeddings",
        descricao="Reconhecimento facial por comparação com a base de pessoas permitidas.",
        icone="👤",
    ),
    "alt2": AlternativaUI(
        codigo="alt2",
        titulo="Alt 2 · FaceCNN",
        descricao="Classificação direta com o modelo FaceCNN afinado.",
        icone="🧠",
    ),
    "alt3": AlternativaUI(
        codigo="alt3",
        titulo="Alt 3 · ResNet50",
        descricao="Classificação direta com o modelo ResNet50 afinado.",
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

