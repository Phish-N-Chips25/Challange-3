"""Interface pública do pacote `frontend`.

Use `autenticar(...)` para validar uma imagem com a alternativa escolhida.
"""

from .servico_autenticacao import autenticar, listar_alternativas, registar_alternativa

__all__ = ["autenticar", "listar_alternativas", "registar_alternativa"]

