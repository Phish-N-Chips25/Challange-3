"""Camada intermédia para autenticação de imagens vindas do frontend.

Esta camada recebe a escolha da alternativa (ex.: ``alt1``) e encaminha a
imagem para o validador correspondente, devolvendo apenas ``True``/``False``.

A implementação foi desenhada para ser extensível: basta registar novas
alternativas no dicionário ou via :func:`registar_alternativa`.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any, Callable, Dict, Union

Autenticador = Callable[..., Union[bool, dict[str, Any]]]
AlvoAutenticador = Union[str, Autenticador]


_ALTERNATIVAS: Dict[str, AlvoAutenticador] = {
    "alt1": "frontend.alt1:validar_pessoa_detalhes",
    "alt2": "frontend.alt2:validar_pessoa_detalhes",
    "alt3": "frontend.alt3:validar_pessoa_detalhes",
}


def registar_alternativa(nome: str, alvo: AlvoAutenticador) -> None:
    """Regista uma alternativa de autenticação.

    ``alvo`` pode ser uma função diretamente ou uma string no formato
    ``"modulo.submodulo:funcao"``.
    """
    if not nome:
        raise ValueError("O nome da alternativa não pode ser vazio.")
    _ALTERNATIVAS[nome.lower()] = alvo


def listar_alternativas() -> tuple[str, ...]:
    """Devolve as alternativas atualmente registadas."""
    return tuple(sorted(_ALTERNATIVAS.keys()))


def _resolver_alternativa(nome: str) -> Autenticador:
    alvo = _ALTERNATIVAS.get(nome.lower())
    if alvo is None:
        raise ValueError(f"Alternativa de autenticação desconhecida: {nome}")

    if callable(alvo):
        return alvo

    if isinstance(alvo, str):
        if ":" not in alvo:
            raise ValueError(
                f"Formato inválido para a alternativa '{nome}'. Esperado 'modulo:funcao'."
            )

        modulo_nome, atributo = alvo.split(":", 1)
        try:
            modulo = import_module(modulo_nome)
        except ModuleNotFoundError as exc:
            # Permite correr `python frontend/app.py`, onde `frontend` pode não estar no PYTHONPATH.
            if modulo_nome.startswith("frontend.") and exc.name in {"frontend", modulo_nome}:
                modulo = import_module(modulo_nome.split(".", 1)[1])
            else:
                raise
        funcao = getattr(modulo, atributo, None)
        if not callable(funcao):
            raise ValueError(
                f"A alternativa '{nome}' aponta para '{alvo}', mas isso não é uma função chamável."
            )
        return funcao

    raise TypeError(f"Tipo inválido de alvo registado para '{nome}': {type(alvo)!r}")


def autenticar(imagem: Any, alternativa: str = "alt1", **kwargs: Any) -> bool:
    """Autentica uma imagem usando a alternativa escolhida.

    Parâmetros adicionais são encaminhados para a alternativa concreta.
    """
    return bool(autenticar_detalhado(imagem, alternativa=alternativa, **kwargs)["allowed"])


def autenticar_detalhado(imagem: Any, alternativa: str = "alt1", **kwargs: Any) -> dict[str, Any]:
    """Autentica uma imagem e devolve detalhes da decisão (inclui threshold/score quando disponível)."""
    autenticador = _resolver_alternativa(alternativa)
    resultado = autenticador(imagem, **kwargs)

    if isinstance(resultado, dict):
        dados = dict(resultado)
        dados.setdefault("allowed", bool(dados.get("allowed", False)))
        if "threshold" not in dados and "threshold" in kwargs:
            dados["threshold"] = kwargs["threshold"]
        return dados

    dados = {
        "allowed": bool(resultado),
    }
    if "threshold" in kwargs:
        dados["threshold"] = kwargs["threshold"]
    return dados


__all__ = ["autenticar", "autenticar_detalhado", "listar_alternativas", "registar_alternativa"]

