"""Alt2: Reconhecimento Facial por Classificação Direta - FaceCNN

ABORDAGEM: Classificação Direta do Modelo
==========================================

Este módulo implementa reconhecimento facial usando um modelo FaceCNN customizado
que foi fine-tuned com as faces das 5 pessoas permitidas. NÃO usa base de dados!

O modelo já "sabe" quem são as 5 pessoas, portanto faz classificação direta
em vez de comparação com base de dados (diferente de Alt1).

FLUXO:
------
1. Detecta rosto com MTCNN
2. Extrai e alinha o rosto (192x192)
3. Passa pelo modelo FaceCNN
4. Obtém outputs (5 neurônios, um por classe)
5. Aplica softmax para obter probabilidades
6. Retorna classe com maior probabilidade
7. Verifica se está acima do threshold (padrão: 0.70)

CLASSES FIXAS (5):
------------------
['Arsenio', 'Cesar', 'Goncalo', 'Rui', 'Rynalde']

VANTAGENS:
----------
- Muito rápido (sem base de dados)
- Sem necessidade de fotos de enrolamento
- Score claro (confiança da classificação)
- Modelo já treinado e pronto

DESVANTAGENS:
-------------
- Classes fixas (só reconhece estas 5 pessoas)
- Para adicionar pessoas, precisa retreinar o modelo
- Modelo específico para estas 5 pessoas

THRESHOLD: 0.70 (probabilidade, 0-1)

EXEMPLO DE USO:
---------------
    from frontend.alt2 import validar_pessoa, validar_pessoa_detalhes
    
    # Validação simples (booleana)
    if validar_pessoa("foto.jpg"):
        print("Autorizado!")
    
    # Validação detalhada
    resultado = validar_pessoa_detalhes("foto.jpg")
    print(f"Pessoa: {resultado['matched_name']}")
    print(f"Confiança: {resultado['score']:.2%}")
    print(f"Allowed: {resultado['allowed']}")
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional, Union

import cv2
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms
from facenet_pytorch import MTCNN
from PIL import Image


# ============================================================
# CONFIGURAÇÃO
# ============================================================
MODELO_PATH = str(Path(__file__).resolve().parent.parent / "RNAAPIA" / "Fine Tuning" / "best_cnn_model.pth")
THRESHOLD_PADRAO = 0.70
PASTA_BD_PADRAO = str((Path(__file__).resolve().parent / "pessoas_permitidas").resolve())
IMAGE_SIZE = 192
CLASS_NAMES = ['Arsenio', 'Cesar', 'Goncalo', 'Rui', 'Rynalde']

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
# ARQUITETURA DO MODELO CNN
# ============================================================
class ConvBlock(nn.Module):
    def __init__(self, in_ch, out_ch):
        super().__init__()
        self.block = nn.Sequential(
            nn.Conv2d(in_ch, out_ch, 3, padding=1, bias=False),
            nn.BatchNorm2d(out_ch),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2)
        )
    def forward(self, x):
        return self.block(x)


class FaceCNN(nn.Module):
    def __init__(self, num_classes, emb=512, sz=192):
        super().__init__()
        self.conv_blocks = nn.Sequential(
            ConvBlock(3, 32),
            ConvBlock(32, 64),
            ConvBlock(64, 128),
            ConvBlock(128, 256)
        )
        fm = sz // 16

        self.embedding = nn.Sequential(
            nn.Flatten(),
            nn.Dropout(0.5),
            nn.Linear(256 * fm * fm, emb),
            nn.BatchNorm1d(emb),
            nn.ReLU(inplace=True)
        )

        self.classifier = nn.Linear(emb, num_classes)

    def forward(self, x):
        e = self.embedding(self.conv_blocks(x))
        return self.classifier(e)


# ============================================================
# INICIALIZAÇÃO LAZY
# ============================================================
@lru_cache(maxsize=1)
def obter_modelo():
    """Carrega e reutiliza o modelo CNN customizado e o MTCNN."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # Carrega o modelo CNN
    model = FaceCNN(num_classes=len(CLASS_NAMES))
    ckpt = torch.load(MODELO_PATH, map_location=device)
    model.load_state_dict(ckpt["model"])
    model = model.to(device)
    model.eval()
    
    # Carrega o MTCNN para deteção
    mtcnn = MTCNN(
        image_size=IMAGE_SIZE,
        margin=IMAGE_SIZE // 6,
        post_process=False,
        keep_all=True,
        device=device
    )
    
    return model, mtcnn, device


# ============================================================
# TRANSFORMS
# ============================================================
tf = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize([0.5]*3, [0.5]*3)
])


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


def classificar_rosto(imagem: np.ndarray, threshold: float = THRESHOLD_PADRAO):
    """Classifica a imagem usando o modelo FaceCNN treinado.
    
    Retorna: (nome_da_classe, score_confianca, permitido)
    
    O modelo foi treinado com as 5 pessoas, então faz classificação direta,
    não comparação com base de dados como Alt1.
    """
    try:
        if imagem is None:
            return None, -1.0, False

        model, mtcnn, device = obter_modelo()

        # Converte para RGB (PIL espera RGB)
        pil_img = Image.fromarray(cv2.cvtColor(imagem, cv2.COLOR_BGR2RGB))

        # Detecta rostos com MTCNN
        boxes, probs = mtcnn.detect(pil_img, landmarks=False)
        if boxes is None or len(boxes) == 0:
            return None, -1.0, False
        
        # Extrai o primeiro rosto
        faces = mtcnn.extract(pil_img, boxes, save_path=None)
        if faces is None or len(faces) == 0:
            return None, -1.0, False
        
        face = faces[0]
        
        # Converte o tensor para imagem se necessário
        if isinstance(face, torch.Tensor):
            face_np = face.permute(1, 2, 0).cpu().numpy().astype(np.uint8)
            face_img = Image.fromarray(face_np)
        else:
            face_img = face
        
        # Aplica transformações
        face_tensor = tf(face_img).unsqueeze(0).to(device)
        
        # Passa pelo modelo para obter classificação
        with torch.no_grad():
            outputs = model(face_tensor)
            probs = torch.nn.functional.softmax(outputs, dim=1)
            score, idx = probs.max(dim=1)
            score = score.item()
            classe_idx = idx.item()
        
        classe_nome = CLASS_NAMES[classe_idx]
        permitido = score >= threshold
        
        return classe_nome, score, permitido
        
    except Exception as exc:
        raise RuntimeError(f"Falha na Alt2 ao processar a imagem: {exc}") from exc


def validar_pessoa(
    imagem: ImagemEntrada,
    threshold: float = THRESHOLD_PADRAO,
) -> bool:
    """Recebe uma imagem e devolve `True` se a pessoa for permitida, caso contrário `False`."""
    resultado = validar_pessoa_detalhes(imagem, threshold=threshold)
    return bool(resultado["allowed"])


def validar_pessoa_detalhes(
    imagem: ImagemEntrada,
    threshold: float = THRESHOLD_PADRAO,
) -> dict[str, Any]:
    """Devolve resultado detalhado com decisão, score e threshold usado.
    
    Esta alternativa usa CLASSIFICAÇÃO DIRETA (o modelo já foi treinado com as pessoas),
    não comparação com base de dados como Alt1.
    """
    frame = carregar_imagem(imagem)
    if frame is None:
        return {
            "allowed": False,
            "score": None,
            "threshold": float(threshold),
            "matched_name": None,
            "reason": "imagem_invalida",
        }

    try:
        nome, score, permitido = classificar_rosto(frame, threshold)
    except Exception as exc:
        return {
            "allowed": False,
            "score": None,
            "threshold": float(threshold),
            "matched_name": None,
            "reason": "erro_interno",
            "error": str(exc),
        }
    
    if nome is None:
        return {
            "allowed": False,
            "score": None,
            "threshold": float(threshold),
            "matched_name": None,
            "reason": "sem_rosto",
        }

    return {
        "allowed": bool(permitido),
        "score": float(score),
        "threshold": float(threshold),
        "matched_name": nome,
        "reason": "ok" if permitido else "abaixo_threshold",
    }


__all__ = ["validar_pessoa", "validar_pessoa_detalhes"]

