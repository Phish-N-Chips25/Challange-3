"""Frontend web simples para autenticação por câmara.

Abre uma página com uma caixa quadrada de vídeo ao vivo e um único botão
"Autenticar". Ao clicar, o frame atual da câmara é enviado ao serviço de
autenticação e o resultado aparece no ecrã.
"""

from __future__ import annotations

import traceback

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.exceptions import HTTPException

try:
    from frontend.servico_autenticacao import autenticar_detalhado, listar_alternativas
    from frontend.ui_registry import obter_alternativa_ui
    from frontend.alt1 import precarregar_recursos_alt1
except ModuleNotFoundError:
    from servico_autenticacao import autenticar_detalhado, listar_alternativas
    from ui_registry import obter_alternativa_ui
    from alt1 import precarregar_recursos_alt1


app = Flask(__name__)
app.secret_key = "neongate-dev-secret-key-change-me"


def _precarregar_alt1_no_arranque() -> None:
    """Aquece recursos da Alt1 para reduzir latência do primeiro /auth."""
    try:
        total = precarregar_recursos_alt1()
        print(f"[startup] Alt1 pre-carregada com {total} pessoa(s) na base cacheada.")
    except Exception as exc:
        # Falha de warmup não deve impedir o arranque da app.
        print(f"[startup] Aviso: falha no pre-carregamento da Alt1: {exc}")


_precarregar_alt1_no_arranque()


HTML = """
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Phish'N'Chips | Login Seguro</title>
  <style>
    :root {
      --bg: #07131f;
      --card: rgba(15, 23, 42, 0.9);
      --line: rgba(148, 163, 184, 0.2);
      --line-soft: rgba(148, 163, 184, 0.12);
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #67e8f9;
      --ok: #4ade80;
      --bad: #f87171;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      color: var(--text);
      background: linear-gradient(135deg, #03111d, var(--bg) 55%, #10223a);
      padding: 24px;
    }
    .shell {
      width: min(980px, 100%);
      margin: 0 auto;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 14px;
      color: var(--muted);
      font-size: 0.9rem;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text);
      font-weight: 700;
    }
    .dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: var(--accent);
      box-shadow: 0 0 12px rgba(125, 211, 252, 0.9);
    }
    .hero {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 22px;
      box-shadow: 0 20px 70px rgba(0, 0, 0, 0.35);
      margin-bottom: 16px;
    }
    h1 {
      margin: 0 0 10px;
      font-size: clamp(1.4rem, 2.5vw, 2rem);
    }
    .subtitle {
      margin: 0;
      color: var(--muted);
      max-width: 70ch;
      line-height: 1.6;
    }
    .grid {
      margin-top: 16px;
      display: grid;
      grid-template-columns: 1fr 300px;
      gap: 16px;
      align-items: start;
    }
    .camera-card,
    .action-card {
      background: rgba(2, 6, 23, 0.45);
      border: 1px solid var(--line-soft);
      border-radius: 16px;
      padding: 14px;
    }
    .section-title {
      font-size: 0.86rem;
      color: var(--muted);
      margin: 0 0 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .square {
      width: 100%;
      aspect-ratio: 1 / 1;
      border-radius: 14px;
      overflow: hidden;
      border: 1px solid var(--line);
      background: #020617;
    }
    video {
      width: 100%;
      height: 100%;
      object-fit: cover;
      transform: scaleX(-1);
    }
    button {
      width: 100%;
      border: 0;
      border-radius: 12px;
      padding: 12px 14px;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      color: #020617;
      background: linear-gradient(90deg, #7dd3fc, #c084fc);
    }
    .status {
      margin-top: 12px;
      border-radius: 12px;
      padding: 12px;
      border: 1px solid var(--line);
      background: rgba(15, 23, 42, 0.92);
      min-height: 78px;
    }
    .status.good { border-color: rgba(74, 222, 128, 0.38); }
    .status.bad { border-color: rgba(248, 113, 113, 0.38); }
    .status .label { color: var(--muted); font-size: 0.82rem; margin-bottom: 6px; }
    .status .value { font-size: 1.02rem; font-weight: 700; }
    .control {
      margin-bottom: 10px;
    }
    .control label {
      display: block;
      color: var(--muted);
      font-size: 0.82rem;
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .control select {
      width: 100%;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: rgba(2, 6, 23, 0.7);
      color: var(--text);
      padding: 10px;
      font-size: 0.95rem;
    }
    .tip {
      margin-top: 10px;
      color: var(--muted);
      font-size: 0.82rem;
      line-height: 1.5;
    }
    @media (max-width: 860px) {
      .grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <div class="topbar">
      <div class="brand"><span class="dot"></span> Phish'N'Chips</div>
      <div>Portal de acesso da equipa</div>
    </div>

    <section class="hero">
      <h1>Login da equipa Phish'N'Chips</h1>
      <p class="subtitle">
        Posiciona o rosto dentro da câmara e valida o acesso com um clique.
        Em caso de sucesso, serás redirecionado automaticamente para a sessão autenticada.
      </p>

      <div class="grid">
        <div class="camera-card">
          <p class="section-title">Câmara</p>
          <div class="square">
            <video id="camera" autoplay playsinline muted></video>
          </div>
        </div>

        <div class="action-card">
          <p class="section-title">Ação</p>
          {% if alternativas|length > 1 %}
          <div class="control">
            <label for="alternativa">Alternativa</label>
            <select id="alternativa" name="alternativa">
              {% for alt in alternativas %}
              <option value="{{ alt.codigo }}" {% if alt.codigo == alternativa_default %}selected{% endif %}>{{ alt.label }}</option>
              {% endfor %}
            </select>
          </div>
          {% endif %}
          <button id="authBtn">Autenticar</button>
          <div id="status" class="status">
            <div class="label">Estado</div>
            <div class="value">Aguardando ação</div>
          </div>
          <p class="tip">Se a câmara não iniciar, aceita a permissão do navegador e atualiza a página.</p>
        </div>
      </div>
    </section>
  </main>

  <script>
    const video = document.getElementById('camera');
    const authBtn = document.getElementById('authBtn');
    const statusBox = document.getElementById('status');
    const alternativaSelect = document.getElementById('alternativa');
    let authInFlight = false;

    const reasonMap = {
      ok: 'OK',
      abaixo_threshold: 'Abaixo do threshold',
      sem_rosto: 'Sem rosto detectado',
      base_vazia: 'Base de dados vazia',
      imagem_invalida: 'Imagem inválida',
      dependencia_ausente: 'Dependência em falta',
      erro_interno: 'Erro interno na alternativa'
    };

    async function startCamera() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'user' },
          audio: false
        });
        video.srcObject = stream;
      } catch (err) {
        statusBox.className = 'status bad';
        statusBox.innerHTML = '<div class="label">Erro</div><div class="value">Sem acesso à câmara</div>';
        console.error(err);
      }
    }

    async function authenticate() {
      if (authInFlight) {
        return;
      }

      if (!video.videoWidth || !video.videoHeight) {
        statusBox.className = 'status bad';
        statusBox.innerHTML = '<div class="label">Erro</div><div class="value">A câmara ainda não está pronta</div>';
        return;
      }

      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.92));
      const formData = new FormData();
      formData.append('frame', blob, 'frame.jpg');
      if (alternativaSelect) {
        formData.append('alternativa', alternativaSelect.value);
      }

      authInFlight = true;
      authBtn.disabled = true;
      statusBox.className = 'status';
      statusBox.innerHTML = '<div class="label">Estado</div><div class="value">A autenticar...</div>';

      try {
        const response = await fetch('/auth', { method: 'POST', body: formData });
        const raw = await response.text();
        let data;
        try {
          data = JSON.parse(raw);
        } catch {
          throw new Error('Resposta inválida do servidor (' + response.status + ')');
        }

        if (!response.ok) {
          throw new Error(data.error || ('Erro HTTP ' + response.status));
        }

        const scoreText = data.score === null || data.score === undefined
          ? 'N/A'
          : Number(data.score).toFixed(3);
        const thresholdText = data.threshold === null || data.threshold === undefined
          ? '-'
          : Number(data.threshold).toFixed(2);
        const reasonText = reasonMap[data.reason] || (data.reason || '-');

          const matchedName = data.matched_name || 'Utilizador';

          if (data.allowed) {
          statusBox.className = 'status good';
            statusBox.innerHTML = '<div class="label">Resultado</div><div class="value">Pessoa permitida: ' + matchedName + '</div>' +
            '<div class="label" style="margin-top:8px;">Score: ' + scoreText + ' | Threshold: ' + thresholdText + '</div>' +
            '<div class="label" style="margin-top:6px;">Motivo: ' + reasonText + '</div>';

            setTimeout(() => {
              const target = data.redirect_to || '/welcome';
              window.location.href = target;
            }, 1200);
        } else {
          statusBox.className = 'status bad';
          statusBox.innerHTML = '<div class="label">Resultado</div><div class="value">Acesso negado</div>' +
            '<div class="label" style="margin-top:8px;">Score: ' + scoreText + ' | Threshold: ' + thresholdText + '</div>' +
            '<div class="label" style="margin-top:6px;">Motivo: ' + reasonText + '</div>';
        }
      } catch (err) {
        statusBox.className = 'status bad';
        const msg = (err && err.message) ? err.message : 'Falha ao autenticar';
        statusBox.innerHTML = '<div class="label">Erro</div><div class="value">' + msg + '</div>';
      } finally {
        authInFlight = false;
        authBtn.disabled = false;
      }
    }

    authBtn.addEventListener('click', authenticate);
    startCamera();
  </script>
</body>
</html>
"""


WELCOME_HTML = """
<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Phish'N'Chips | Sessão</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: linear-gradient(135deg, #020617, #0f172a 55%, #111827);
      color: #e2e8f0;
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      padding: 24px;
    }
    .card {
      width: min(680px, 100%);
      border-radius: 22px;
      border: 1px solid rgba(148, 163, 184, 0.22);
      background: rgba(15, 23, 42, 0.88);
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
      padding: 30px;
      text-align: center;
    }
    .kicker {
      font-size: 12px;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: #38bdf8;
      margin-bottom: 10px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: clamp(2rem, 5vw, 2.8rem);
      background: linear-gradient(90deg, #7dd3fc, #c084fc, #f9a8d4);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    p {
      color: #94a3b8;
      margin: 0;
      line-height: 1.7;
      font-size: 1rem;
    }
    .name {
      color: #f8fafc;
      font-weight: 700;
    }
    button {
      margin-top: 22px;
      width: 100%;
      border: 0;
      border-radius: 14px;
      padding: 14px 18px;
      font-size: 16px;
      font-weight: 700;
      cursor: pointer;
      color: #020617;
      background: linear-gradient(90deg, #7dd3fc, #c084fc);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="kicker">Phish'N'Chips</div>
    <h1>Bem Vindo de Volta <span class="name">{{ nome }}</span></h1>
    <p>Autenticado com <strong>{{ nome }}</strong>.</p>
    <form method="post" action="{{ url_for('logout') }}">
      <button type="submit">Terminar sessão</button>
    </form>
  </div>
</body>
</html>
"""


@app.get("/")
def home():
    alternativas_codigos = list(listar_alternativas())
    if not alternativas_codigos:
        alternativas_codigos = ["alt1"]

    alternativas = []
    for codigo in alternativas_codigos:
        try:
            meta = obter_alternativa_ui(codigo)
            label = f"{meta.icone} {meta.titulo}"
        except Exception:
            label = codigo
        alternativas.append({"codigo": codigo, "label": label})

    return render_template_string(
        HTML,
        alternativas=alternativas,
        alternativa_default=alternativas_codigos[0],
    )


@app.post("/auth")
def auth():
    try:
        frame = request.files.get("frame")
        if frame is None:
            return jsonify({"allowed": False, "error": "frame ausente"}), 400

        frame_bytes = frame.read()
        if not frame_bytes:
            return jsonify({"allowed": False, "error": "frame vazio"}), 400

        alternativas_validas = set(listar_alternativas())
        alternativa = (request.form.get("alternativa") or "").strip().lower()
        if alternativa not in alternativas_validas:
            alternativa = "alt1" if "alt1" in alternativas_validas else next(iter(alternativas_validas), "alt1")

        resultado = autenticar_detalhado(frame_bytes, alternativa=alternativa)
    except ModuleNotFoundError as exc:
        return jsonify(
            {
                "allowed": False,
                "score": None,
                "threshold": None,
                "matched_name": None,
                "reason": "dependencia_ausente",
                "error": f"Módulo em falta: {exc.name}",
            }
        ), 500
    except HTTPException as exc:
        return jsonify(
            {
                "allowed": False,
                "score": None,
                "threshold": None,
                "matched_name": None,
                "reason": "erro_http",
                "error": exc.description,
            }
        ), exc.code
    except Exception as exc:
        traceback.print_exc()
        return jsonify(
            {
                "allowed": False,
                "score": None,
                "threshold": None,
                "matched_name": None,
                "reason": "erro_interno",
                "error": str(exc),
            }
        ), 500

    if resultado.get("allowed"):
        nome = resultado.get("matched_name") or "Utilizador"
        session["auth_name"] = nome
        resultado["redirect_to"] = url_for("welcome")
    return jsonify(resultado)


@app.get("/welcome")
def welcome():
    nome = session.get("auth_name")
    if not nome:
        return redirect(url_for("home"))
    return render_template_string(WELCOME_HTML, nome=nome)


@app.post("/logout")
def logout():
    session.pop("auth_name", None)
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

