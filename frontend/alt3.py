"""Alt3: Reconhecimento Facial por Classificação Direta - ResNet50

ABORDAGEM: Classificação Direta do Modelo
==========================================

Este módulo implementa reconhecimento facial usando um modelo ResNet50 customizado
que foi fine-tuned com as faces das 5 pessoas permitidas. NÃO usa base de dados!

Idêntico a Alt2 (classificação direta) mas com ResNet50 como backbone em vez de CNN.
ResNet50 é um modelo mais profundo e geralmente mais robusto.

FLUXO:
------
1. Detecta rosto com MTCNN
2. Extrai e alinha o rosto (192x192)
3. Passa pelo modelo ResNet50 fine-tuned
4. Obtém outputs (5 neurônios, um por classe)
5. Aplica softmax para obter probabilidades
6. Retorna classe com maior probabilidade
7. Verifica se está acima do threshold (padrão: 0.60)

CLASSES FIXAS (5):
------------------
['Arsenio', 'Cesar', 'Goncalo', 'Rui', 'Rynalde']

VANTAGENS:
----------
- Muito rápido (sem base de dados)
- ResNet50 é mais robusto que CNN custom
- Melhor generalização
- Sem necessidade de fotos de enrolamento
- Score claro (confiança da classificação)
- Modelo já treinado e pronto

DESVANTAGENS:
-------------
- Classes fixas (só reconhece estas 5 pessoas)
- Para adicionar pessoas, precisa retreinar o modelo
- Modelo específico para estas 5 pessoas

THRESHOLD: 0.60 (probabilidade, 0-1)
Nota: Threshold mais baixo que Alt2 porque ResNet50 tende a ter maior confiança

COMPARAÇÃO COM ALT2:
--------------------
┌─────────────┬──────────┬──────────┐
│ Aspecto     │ Alt2 CNN │ Alt3 RN50│
├─────────────┼──────────┼──────────┤
│ Velocidade  │ ⚡⚡     │ ⚡⚡     │
│ Robustez    │ ✓        │ ✓✓       │
│ Confiança   │ Média    │ Alta     │
│ Threshold   │ 0.70     │ 0.60     │
└─────────────┴──────────┴──────────┘

EXEMPLO DE USO:
---------------
    from frontend.alt3 import validar_pessoa, validar_pessoa_detalhes
    
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
import torchvision.models as tv_models
from facenet_pytorch import MTCNN
from PIL import Image


# ============================================================
# CONFIGURAÇÃO
# ============================================================
MODELO_PATH = str(Path(__file__).resolve().parent.parent / "RNAAPIA" / "Fine Tuning" / "best_resnet_model.pth")
THRESHOLD_PADRAO = 0.60
PASTA_BD_PADRAO = str((Path(__file__).resolve().parent / "pessoas_permitidas").resolve())
IMAGE_SIZE = 192
CLASS_NAMES = ['Arsenio', 'Cesar', 'Goncalo', 'Rui', 'Rynalde']

ImagemEntrada = Union[str, os.PathLike[str], bytes, np.ndarray]


# ============================================================
# ARQUITETURA DO MODELO RESNET
# ============================================================
class ResNet50Face(nn.Module):
    def __init__(self, num_classes, emb=512):
        super().__init__()
        backbone = tv_models.resnet50(weights=None)
        self.features = nn.Sequential(*list(backbone.children())[:-1])

        self.embedding = nn.Sequential(
            nn.Flatten(),
            nn.Dropout(0.5),
            nn.Linear(2048, emb),
            nn.BatchNorm1d(emb),
            nn.ReLU(inplace=True)
        )

        self.classifier = nn.Linear(emb, num_classes)

    def forward(self, x):
        e = self.embedding(self.features(x))
        return self.classifier(e)


# ============================================================
# INICIALIZAÇÃO LAZY
# ============================================================
@lru_cache(maxsize=1)
def obter_modelo():
    """Carrega e reutiliza o modelo ResNet customizado e o MTCNN."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # Carrega o modelo ResNet
    model = ResNet50Face(num_classes=len(CLASS_NAMES))
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
        return cv2.imread(caminho)

    return None



def classificar_rosto(imagem: np.ndarray, threshold: float = THRESHOLD_PADRAO):
    """Classifica a imagem usando o modelo ResNet50 treinado.
    
    Retorna: (nome_da_classe, score_confianca, permitido)
    
    O modelo foi treinado com as 5 pessoas, então faz classificação direta,
    não comparação com base de dados como Alt1.
    """
    if imagem is None:
        return None, -1.0, False
    
    model, mtcnn, device = obter_modelo()
    
    # Converte para RGB (PIL espera RGB)
    pil_img = Image.fromarray(cv2.cvtColor(imagem, cv2.COLOR_BGR2RGB))
    
    # Detecta rostos com MTCNN
    try:
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
        
    except Exception:
        return None, -1.0, False


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

    nome, score, permitido = classificar_rosto(frame, threshold)
    
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

