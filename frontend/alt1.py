"""Alt1: Reconhecimento Facial por Matching de Embeddings - InsightFace

ABORDAGEM: Comparação de Embeddings com Base de Dados
========================================================

Este módulo implementa reconhecimento facial usando InsightFace (buffalo_sc).
Funciona comparando o embedding de uma nova imagem com centróides de embeddings
armazenados em uma base de dados (pasta pessoas_permitidas/).

FLUXO:
------
1. Carrega fotos de enrolamento de pessoas_permitidas/
2. Extrai embeddings usando InsightFace
3. Calcula centroide de embeddings por pessoa (normalizado)
4. Quando nova imagem chega:
   - Extrai embedding
   - Compara com todos os centróides usando similaridade cosseno
   - Retorna pessoa mais próxima
   - Verifica se está acima do threshold (padrão: 0.75)

VANTAGENS:
----------
- Flexível: Adiciona pessoas sem retreinar
- Sem treino necessário
- Escalável para muitas pessoas
- Usa InsightFace pré-treinado (ONNX)

DESVANTAGENS:
-------------
- Requer base de dados (pasta pessoas_permitidas)
- Precisa múltiplas fotos por pessoa para bom centroide
- Score depende da qualidade da base de dados

THRESHOLD: 0.75 (similaridade cosseno, 0-1)

EXEMPLO DE USO:
---------------
    from frontend.alt1 import validar_pessoa, validar_pessoa_detalhes
    
    # Validação simples (booleana)
    if validar_pessoa("foto.jpg"):
        print("Autorizado!")
    
    # Validação detalhada
    resultado = validar_pessoa_detalhes("foto.jpg")
    print(f"Pessoa: {resultado['matched_name']}")
    print(f"Score: {resultado['score']:.4f}")
    print(f"Allowed: {resultado['allowed']}")
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, Union

import cv2
import numpy as np
from insightface.app import FaceAnalysis
from sklearn.metrics.pairwise import cosine_similarity


# ============================================================
# CONFIGURAÇÃO
# ============================================================
MODELO = "buffalo_sc"  # Trocar para buffalo_l se quiseres outra backbone
THRESHOLD_PADRAO = 0.75
# Usa caminho absoluto relativo a este ficheiro para evitar "base vazia" por CWD diferente.
PASTA_BD_PADRAO = str((Path(__file__).resolve().parent / "pessoas_permitidas").resolve())
DET_SIZE = (640, 640)

ImagemEntrada = Union[str, os.PathLike[str], bytes, np.ndarray]


def _ler_imagem_path(caminho: str) -> Optional[np.ndarray]:
    """Lê imagem de disco de forma robusta para paths Unicode no Windows."""
    try:
        buffer = np.fromfile(caminho, dtype=np.uint8)
    except OSError:
        return None
    if buffer.size == 0:
        return None
    return cv2.imdecode(buffer, cv2.IMREAD_COLOR)


# ============================================================
# INICIALIZAÇÃO LAZY
# ============================================================
@lru_cache(maxsize=1)
def obter_modelo() -> FaceAnalysis:
    """Carrega e reutiliza o modelo de face recognition."""
    app = FaceAnalysis(name=MODELO, providers=["CPUExecutionProvider"])
    app.prepare(ctx_id=0, det_size=DET_SIZE)
    return app


# ============================================================
# UTILITÁRIOS DE IMAGEM
# ============================================================
def carregar_imagem(entrada: ImagemEntrada) -> Optional[np.ndarray]:
    """Aceita caminho, bytes ou uma imagem OpenCV/Numpy e devolve um frame BGR."""
    if isinstance(entrada, np.ndarray):
        return entrada

    if isinstance(entrada, (bytes, bytearray)):
        buffer = np.frombuffer(entrada, dtype=np.uint8)
        imagem = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
        return imagem

    if isinstance(entrada, (str, os.PathLike)):
        caminho = os.fspath(entrada)
        return _ler_imagem_path(caminho)

    return None


def extrair_embedding(imagem: np.ndarray, app: Optional[FaceAnalysis] = None) -> Optional[np.ndarray]:
    """Extrai o embedding do primeiro rosto detetado na imagem."""
    if imagem is None:
        return None

    app = app or obter_modelo()
    rostos = app.get(imagem)
    if rostos:
        return rostos[0].embedding
    return None


# ============================================================
# CONSTRUÇÃO DA BASE DE DADOS (com centroide)
# ============================================================
def carregar_base_de_dados(pasta: ImagemEntrada = PASTA_BD_PADRAO, app: Optional[FaceAnalysis] = None):
    """
    Carrega as fotos de enrolamento e calcula o centroide dos embeddings
    de cada pessoa. Guarda apenas 1 vetor representativo por pessoa.
    """
    app = app or obter_modelo()
    base_de_dados = {}

    pasta_path = Path(pasta)
    if not pasta_path.exists():
        return base_de_dados

    for pessoa_dir in pasta_path.iterdir():
        if not pessoa_dir.is_dir():
            continue

        embeddings = []
        for foto_path in pessoa_dir.iterdir():
            if foto_path.suffix.lower() not in {".jpg", ".jpeg", ".png", ".bmp", ".webp"}:
                continue

            imagem = _ler_imagem_path(str(foto_path))
            if imagem is None:
                continue

            emb = extrair_embedding(imagem, app)
            if emb is not None:
                embeddings.append(emb)

            emb_flip = extrair_embedding(cv2.flip(imagem, 1), app)
            if emb_flip is not None:
                embeddings.append(emb_flip)

        if embeddings:
            centroide = np.mean(embeddings, axis=0)
            norma = np.linalg.norm(centroide)
            if norma > 0:
                base_de_dados[pessoa_dir.name] = centroide / norma

    return base_de_dados


# ============================================================
# RECONHECIMENTO
# ============================================================
def reconhecer_rosto(embedding_query: np.ndarray, base_de_dados, threshold: float = THRESHOLD_PADRAO):
    """Devolve o melhor candidato, o score e a decisão booleana."""
    melhor_nome = None
    melhor_score = -1.0

    for nome, centroide in base_de_dados.items():
        score = cosine_similarity(
            embedding_query.reshape(1, -1),
            centroide.reshape(1, -1),
        )[0][0]

        if score > melhor_score:
            melhor_score = score
            melhor_nome = nome

    permitido = melhor_score >= threshold
    return melhor_nome, melhor_score, permitido


def validar_pessoa(
    imagem: ImagemEntrada,
    pasta_bd: ImagemEntrada = PASTA_BD_PADRAO,
    threshold: float = THRESHOLD_PADRAO,
    base_de_dados=None,
    app: Optional[FaceAnalysis] = None,
) -> bool:
    """Recebe uma imagem e devolve `True` se a pessoa for permitida, caso contrário `False`."""
    resultado = validar_pessoa_detalhes(
        imagem,
        pasta_bd=pasta_bd,
        threshold=threshold,
        base_de_dados=base_de_dados,
        app=app,
    )
    return bool(resultado["allowed"])


def validar_pessoa_detalhes(
    imagem: ImagemEntrada,
    pasta_bd: ImagemEntrada = PASTA_BD_PADRAO,
    threshold: float = THRESHOLD_PADRAO,
    base_de_dados=None,
    app: Optional[FaceAnalysis] = None,
) -> dict[str, Any]:
    """Devolve resultado detalhado com decisão, score e threshold usado."""
    app = app or obter_modelo()
    frame = carregar_imagem(imagem)
    if frame is None:
        return {
            "allowed": False,
            "score": None,
            "threshold": float(threshold),
            "matched_name": None,
            "reason": "imagem_invalida",
        }

    base_de_dados = base_de_dados if base_de_dados is not None else carregar_base_de_dados(pasta_bd, app)
    if not base_de_dados:
        return {
            "allowed": False,
            "score": None,
            "threshold": float(threshold),
            "matched_name": None,
            "reason": "base_vazia",
        }

    embedding = extrair_embedding(frame, app)
    if embedding is None:
        return {
            "allowed": False,
            "score": None,
            "threshold": float(threshold),
            "matched_name": None,
            "reason": "sem_rosto",
        }

    nome, score, permitido = reconhecer_rosto(embedding, base_de_dados, threshold)
    return {
        "allowed": bool(permitido),
        "score": float(score),
        "threshold": float(threshold),
        "matched_name": nome,
        "reason": "ok" if permitido else "abaixo_threshold",
    }


__all__ = ["validar_pessoa", "validar_pessoa_detalhes"]
