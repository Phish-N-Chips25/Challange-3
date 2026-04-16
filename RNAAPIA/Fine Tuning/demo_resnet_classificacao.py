#!/usr/bin/env python3

import torch
import torch.nn as nn
import torch.nn.functional as F
import torchvision.transforms as transforms
import torchvision.models as tv_models

import cv2
import time
from facenet_pytorch import MTCNN
from PIL import Image
import numpy as np

# =========================
# CONFIG
# =========================
CHECKPOINT = "best_resnet_org.pth"
IMAGE_SIZE = 192
THRESHOLD = 0.60

# ⚠️ IMPORTANTE: ORDEM IGUAL AO TREINO
class_names = ['Arsenio', 'Cesar', 'Goncalo', 'Rui', 'Rynalde']

# =========================
# MODELO
# =========================
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

# =========================
# DEVICE + LOAD
# =========================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

ckpt = torch.load(CHECKPOINT, map_location=device)

model = ResNet50Face(num_classes=len(class_names)).to(device)
model.load_state_dict(ckpt["model"])
model.eval()

# =========================
# MTCNN
# =========================
mtcnn = MTCNN(
    image_size=IMAGE_SIZE,
    margin=IMAGE_SIZE // 6,
    post_process=False,
    keep_all=True,
    device=device
)

# =========================
# TRANSFORMS
# =========================
tf = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize([0.5]*3, [0.5]*3)
])

# =========================
# FUNÇÃO UI
# =========================
def draw_ui(frame, label, score, fps):

    h, w, _ = frame.shape

    # HEADER
    cv2.rectangle(frame, (0, 0), (w, 60), (30, 30, 30), -1)
    cv2.putText(frame, "RNAAPIA - Face Recognition",
                (20, 40),
                cv2.FONT_HERSHEY_SIMPLEX,
                1, (255, 255, 255), 2)

    # FPS
    cv2.putText(frame, f"FPS: {fps:.1f}",
                (w - 150, 40),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.8, (200, 200, 200), 2)

    # FOOTER
    cv2.rectangle(frame, (0, h - 40), (w, h), (30, 30, 30), -1)
    cv2.putText(frame, "Press Q or ESC to exit",
                (20, h - 10),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6, (200, 200, 200), 1)

    # RESULT BOX
    if label is not None:
        color = (0, 200, 0) if label != "DESCONHECIDO" else (0, 0, 255)

        cv2.rectangle(frame, (20, 80), (400, 160), (40, 40, 40), -1)
        cv2.rectangle(frame, (20, 80), (400, 160), color, 2)

        cv2.putText(frame, label,
                    (40, 120),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    1.0, color, 2)

        cv2.putText(frame, f"Confidence: {score:.2f}",
                    (40, 150),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.6, (200, 200, 200), 1)

# =========================
# WEBCAM
# =========================
cap = cv2.VideoCapture(0)

prev_time = time.time()

print("Sistema iniciado")

while True:
    ret, frame = cap.read()
    if not ret:
        break

    # FPS
    current_time = time.time()
    fps = 1 / (current_time - prev_time)
    prev_time = current_time

    label = None
    score = 0.0

    pil = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
    boxes, probs = mtcnn.detect(pil)

    if boxes is not None and probs is not None:

        faces = mtcnn.extract(pil, boxes, save_path=None)

        for box, prob, face in zip(boxes, probs, faces):

            if prob is None or prob < 0.90 or face is None:
                continue

            if isinstance(face, torch.Tensor):
                face_np = face.permute(1, 2, 0).cpu().numpy().astype(np.uint8)
                face_img = Image.fromarray(face_np)
            else:
                face_img = face

            x = tf(face_img).unsqueeze(0).to(device)

            with torch.no_grad():
                outputs = model(x)
                probs_cls = F.softmax(outputs, dim=1)

                score, idx = probs_cls.max(dim=1)
                score = score.item()
                idx = idx.item()

            x1, y1, x2, y2 = [int(v) for v in box]

            if score >= THRESHOLD:
                label = class_names[idx]
                color = (0, 200, 0)
            else:
                label = "DESCONHECIDO"
                color = (0, 0, 255)

            # BOX FACE
            cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)

            # TEXTO EM CIMA DA FACE
            cv2.putText(frame,
                        f"{label} ({score:.2f})",
                        (x1, y1 - 10),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.6, color, 2)

            break  # só primeira face

    # UI overlay
    draw_ui(frame, label, score, fps)

    cv2.imshow("RNAAPIA UI", frame)

    key = cv2.waitKey(1) & 0xFF
    if key == ord("q") or key == 27:  # ESC
        break

cap.release()
cv2.destroyAllWindows()