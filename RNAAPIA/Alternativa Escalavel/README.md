# Sistema de Reconhecimento Facial com `insightface`

Este projeto implementa um **sistema de controlo de acesso baseado em reconhecimento facial**, usando o **`insightface`** para extração de embeddings e OpenCV para captura de vídeo em tempo real.

---

## 🔹 Funcionalidades

* Detecção de rostos em tempo real via câmera.
* Extração de **embeddings faciais** com modelos ArcFace (`buffalo_sc` ou `buffalo_l`).
* Comparação com base de dados de pessoas permitidas usando **cosine similarity**.
* Calibração dinâmica do **threshold** para decisão de acesso.
* Exibição de bounding boxes, score de similaridade e estado (Permitido/Negado).

---

## ⚙️ Dependências

Para correr o sistema, precisas do Python ≥ 3.8 e das seguintes bibliotecas:

```bash
pip install insightface
pip install onnxruntime
pip install opencv-python
pip install numpy
pip install scikit-learn
```

> Nota: Se planeias usar GPU para aceleração, instala `onnxruntime-gpu` em vez de `onnxruntime`.

### 📂 Estrutura da base de dados

A pasta **`pessoas_permitidas/`** deve ter uma subpasta por pessoa, cada uma contendo fotos de treino (JPEG/PNG). Exemplo:

```
pessoas_permitidas/
├─ Rui/
│  ├─ foto1.jpg
│  └─ foto2.jpg
├─ Ana/
│  ├─ img1.png
│  └─ img2.png
```

---

## 🧠 Como funciona o sistema

### 1️⃣ Inicialização do modelo

```python
app = FaceAnalysis(name='buffalo_sc', providers=['CPUExecutionProvider'])
app.prepare(ctx_id=0, det_size=(640, 640))
```

* `buffalo_sc`: modelo compacto e rápido.
* `buffalo_l`: modelo mais preciso (ResNet-50 + ArcFace).
* `det_size`: tamanho da imagem para detecção.

---

### 2️⃣ Extração de embeddings

```python
def extrair_embedding(imagem):
    rostos = app.get(imagem)
    if rostos:
        return rostos[0].embedding
    return None
```

* Cada rosto é convertido num **vetor numérico** que representa características faciais.
* Embeddings são normalizados para **norma unitária** antes de comparação.

---

### 3️⃣ Construção da base de dados

* Para cada pessoa, o sistema calcula o **centroide** dos embeddings das fotos de treino:

```python
centroide = np.mean(embeddings, axis=0)
centroide = centroide / np.linalg.norm(centroide)
```

**Vantagens do centroide:**

* Reduz memória e complexidade.
* Mais robusto a outliers.
* Facilita inferência em tempo real.

---

### 4️⃣ Comparação de embeddings

* Métrica usada: **Cosine Similarity**

```python
score = cosine_similarity(embedding_query.reshape(1, -1),
                          centroide.reshape(1, -1))[0][0]
```

* **Score → 1.0:** muito semelhante; **0:** completamente diferente.
* Threshold definido pelo utilizador decide se o acesso é permitido.

---

### 5️⃣ Reconhecimento em tempo real

* Para cada frame capturado pela câmera:

1. Detecta rostos.
2. Extrai embeddings.
3. Compara com centroides da base de dados.
4. Mostra bounding box, score e estado (Permitido/Negado) na tela.

* Teclas interativas:

  * `Q` → sair do sistema
  * `+` / `-` → ajustar threshold em tempo real

---

## 🔍 Comparação entre embeddings e thresholds

| Modelo     | Dimensão Embedding | Precisão | Velocidade | Observações                       |
| ---------- | ------------------ | -------- | ---------- | --------------------------------- |
| buffalo_sc | 512                | Média    | Alta       | Bom para CPU e aplicações rápidas |
| buffalo_l  | 512                | Alta     | Média      | Mais preciso, pesado para CPU     |

* **Threshold sugerido:** 0.75 (ajustável conforme precisão desejada)
* Threshold mais alto → menos falsos positivos, mais falsos negativos.
* Threshold mais baixo → mais permissivo, pode dar falsos positivos.

---

## 💻 Como correr

1. Instalar dependências:

```bash
pip install insightface onnxruntime opencv-python numpy scikit-learn
```

2. Criar a base de dados:

```
pessoas_permitidas/
└─ Pessoa/
   ├─ foto1.jpg
   └─ foto2.jpg
```

3. Executar o script:

```bash
python main.py
```

4. Ajustar threshold com `+` e `-`.
5. Fechar o sistema com `Q`.

---

