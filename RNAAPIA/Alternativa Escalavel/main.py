import cv2
import numpy as np
import os
from sklearn.metrics.pairwise import cosine_similarity
from insightface.app import FaceAnalysis

# ============================================================
# CONFIGURAÇÃO
# ============================================================
MODELO = 'buffalo_sc'          # Trocar de buffalo_sc para buffalo_l (ResNet-50 + ArcFace)
THRESHOLD = 0.70               # Ajustar consoante resultados (ver scores no ecrã)
PASTA_BD = "pessoas_permitidas"
DET_SIZE = (640, 640)

# ============================================================
# INICIALIZAÇÃO
# ============================================================
print(f"A inicializar modelo '{MODELO}'...")
app = FaceAnalysis(name=MODELO, providers=['CPUExecutionProvider'])
app.prepare(ctx_id=0, det_size=DET_SIZE)
print("Modelo carregado.")


# ============================================================
# EXTRAÇÃO DE EMBEDDING
# ============================================================
def extrair_embedding(imagem):
    """Extrai o embedding do primeiro rosto detetado na imagem."""
    rostos = app.get(imagem)
    if rostos:
        return rostos[0].embedding
    return None


# ============================================================
# CONSTRUÇÃO DA BASE DE DADOS (com centroide)
# ============================================================
def carregar_base_de_dados(pasta=PASTA_BD):
    """
    Carrega as fotos de enrolamento e calcula o centroide dos embeddings
    de cada pessoa. Guarda apenas 1 vetor representativo por pessoa,
    em vez de todos os embeddings individuais.
    """
    base_de_dados = {}

    if not os.path.exists(pasta):
        print(f"[AVISO] Pasta '{pasta}' não encontrada. A criar...")
        os.makedirs(pasta)
        return base_de_dados

    for pessoa in os.listdir(pasta):
        caminho_pessoa = os.path.join(pasta, pessoa)
        if not os.path.isdir(caminho_pessoa):
            continue

        embeddings = []
        for foto in os.listdir(caminho_pessoa):
            if not foto.lower().endswith(('.jpg', '.jpeg', '.png')):
                continue

            caminho_foto = os.path.join(caminho_pessoa, foto)
            imagem = cv2.imread(caminho_foto)
            if imagem is None:
                print(f"  [AVISO] Não foi possível ler: {foto}")
                continue

            # Foto original
            emb = extrair_embedding(imagem)
            if emb is not None:
                embeddings.append(emb)
                print(f"  [OK] {pessoa} / {foto}")
            else:
                print(f"  [AVISO] Rosto não detetado em: {foto}")

            # Versão espelhada (data augmentation no enrolamento)
            emb_flip = extrair_embedding(cv2.flip(imagem, 1))
            if emb_flip is not None:
                embeddings.append(emb_flip)

        if embeddings:
            # Calcula o centroide em vez de guardar todos os embeddings
            # O centroide é mais robusto a outliers e torna a inferência mais rápida
            centroide = np.mean(embeddings, axis=0)
            # Re-normalizar o centroide para norma unitária (importante para cosine similarity)
            centroide = centroide / np.linalg.norm(centroide)
            base_de_dados[pessoa] = centroide
            print(f"  -> Centroide calculado com {len(embeddings)} embeddings ({len(embeddings)//2} fotos + flips)\n")

    print(f"[INFO] Pessoas na base de dados: {list(base_de_dados.keys())}")
    return base_de_dados


# ============================================================
# RECONHECIMENTO
# ============================================================
def reconhecer_rosto(embedding_query, base_de_dados, threshold=THRESHOLD):
    """
    Compara o embedding da câmara com os centroides da base de dados.
    Devolve sempre o melhor nome candidato e o score real,
    independentemente do threshold — a decisão de acesso é feita fora.
    """
    melhor_nome = None
    melhor_score = -1.0

    for nome, centroide in base_de_dados.items():
        score = cosine_similarity(
            embedding_query.reshape(1, -1),
            centroide.reshape(1, -1)
        )[0][0]

        if score > melhor_score:
            melhor_score = score
            melhor_nome = nome

    # Decisão separada da métrica — facilita calibração do threshold
    if melhor_score >= threshold:
        return melhor_nome, melhor_score, True   # (nome, score, permitido)
    else:
        return "DESCONHECIDO", melhor_score, False


# ============================================================
# PROGRAMA PRINCIPAL
# ============================================================
print(f"\nA carregar base de dados de '{PASTA_BD}'...")
base_de_dados = carregar_base_de_dados(PASTA_BD)

if not base_de_dados:
    print("[AVISO] Nenhuma pessoa na base de dados.")
    print(f"Cria a pasta '{PASTA_BD}/' com subpastas por pessoa e fotos dentro.")

print("\nA iniciar câmera...")
camera = cv2.VideoCapture(0)
if not camera.isOpened():
    print("[ERRO] Não foi possível abrir a câmera!")
    exit()

print(f"Sistema iniciado | Modelo: {MODELO} | Threshold: {THRESHOLD}")
print("Prima 'Q' para sair | '+'/'-' para ajustar threshold em tempo real")

while True:
    ret, frame = camera.read()
    if not ret:
        break

    rostos = app.get(frame)

    for rosto in rostos:
        x1, y1, x2, y2 = rosto.bbox.astype(int)

        if base_de_dados:
            nome, score, permitido = reconhecer_rosto(rosto.embedding, base_de_dados, THRESHOLD)
        else:
            nome, score, permitido = "DESCONHECIDO", 0.0, False

        # Cores e labels
        if permitido:
            cor = (0, 220, 0)
            label_estado = f"PERMITIDO: {nome}"
        else:
            cor = (0, 0, 220)
            label_estado = "NEGADO"

        # Score real sempre visível — essencial para calibrar o threshold
        label_score = f"score: {score:.3f} | threshold: {THRESHOLD:.2f}"

        # Bounding box
        cv2.rectangle(frame, (x1, y1), (x2, y2), cor, 2)

        # Label de estado (acima do rosto)
        cv2.putText(frame, label_estado, (x1, y1 - 28),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.65, cor, 2)

        # Score e threshold (linha abaixo do estado)
        cv2.putText(frame, label_score, (x1, y1 - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.50, cor, 1)

    # Threshold atual no canto superior esquerdo
    cv2.putText(frame, f"Threshold: {THRESHOLD:.2f}  (+/-  para ajustar)",
                (10, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (200, 200, 200), 1)

    cv2.imshow("Sistema de Controlo de Acesso", frame)

    tecla = cv2.waitKey(1) & 0xFF
    if tecla == ord('q'):
        break
    elif tecla == ord('+'):
        THRESHOLD = min(THRESHOLD + 0.01, 0.99)
        print(f"[THRESHOLD] -> {THRESHOLD:.2f}")
    elif tecla == ord('-'):
        THRESHOLD = max(THRESHOLD - 0.01, 0.10)
        print(f"[THRESHOLD] -> {THRESHOLD:.2f}")

camera.release()
cv2.destroyAllWindows()
print("Sistema encerrado.")
