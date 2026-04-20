"""Frontend web — facial authentication + SOC threat dashboard.

Auth flow  : camera → InsightFace → session → /dashboard
Detection  : detection_service.py (TransformerAE + single-event AE + RAG + Ollama)
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, render_template_string, request, session, url_for
from werkzeug.exceptions import HTTPException

try:
    from frontend.servico_autenticacao import autenticar_detalhado, listar_alternativas
    from frontend.ui_registry import obter_alternativa_ui
    from frontend.alt1 import precarregar_recursos_alt1
except ModuleNotFoundError:
    from servico_autenticacao import autenticar_detalhado, listar_alternativas
    from ui_registry import obter_alternativa_ui
    from alt1 import precarregar_recursos_alt1

# ── Detection pipeline (cyber-anomaly-detection/) ─────────────────────────────
_DETECTION_ROOT = Path(__file__).resolve().parent.parent / "cyber-anomaly-detection"
sys.path.insert(0, str(_DETECTION_ROOT))
import detection_service as _ds

# ── DualSentinel pipeline ──────────────────────────────────────────────────────
import threading
import uuid

_DS_ROOT    = Path(__file__).resolve().parent.parent / "DualSentinel" / "src"
_DS_SAMPLES = Path(__file__).resolve().parent.parent / "DualSentinel" / "data" / "samples"
sys.path.insert(0, str(_DS_ROOT))

_ds2_runs: dict[str, dict] = {}
_ds2_lock = threading.Lock()

# Ollama config — override via env vars
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",    "phi4:14b")
OLLAMA_TIMEOUT  = int(os.getenv("OLLAMA_TIMEOUT", "600"))


app = Flask(__name__)
app.secret_key = "neongate-dev-secret-key-change-me"
app.config["TEMPLATES_AUTO_RELOAD"] = True


def _env_bool(nome: str, default: bool = False) -> bool:
    valor = os.getenv(nome)
    if valor is None:
        return default
    return valor.strip().lower() in {"1", "true", "yes", "on"}


def _precarregar_alt1_no_arranque() -> None:
    """Aquece recursos da Alt1 para reduzir latência do primeiro /auth."""
    try:
        total = precarregar_recursos_alt1()
        print(f"[startup] Alt1 pre-carregada com {total} pessoa(s) na base cacheada.")
    except Exception as exc:
        print(f"[startup] Aviso: falha no pre-carregamento da Alt1: {exc}")


def _precarregar_detection_no_arranque() -> None:
    """Pre-warm detection models (AE + TransformerAE + ChromaDB) at startup."""
    try:
        print("[startup] A carregar modelos de detecção (pode demorar ~30s)...")
        _ds.load_all()
        ollama_ok, models = _ds.check_ollama(OLLAMA_BASE_URL, OLLAMA_MODEL)
        status = f"disponível ({OLLAMA_MODEL})" if ollama_ok else f"não detectado (modelo: {OLLAMA_MODEL})"
        print(f"[startup] Modelos de detecção carregados. Ollama: {status}")
        if not ollama_ok:
            print(f"[startup] Para activar LLM: ollama serve && ollama pull {OLLAMA_MODEL}")
    except Exception as exc:
        print(f"[startup] Aviso: falha no pre-carregamento da detecção: {exc}")


_precarregar_alt1_no_arranque()
_precarregar_detection_no_arranque()


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
      overflow-x: hidden;
    }
    body::before,
    body::after {
      content: '';
      position: fixed;
      width: 380px;
      height: 380px;
      border-radius: 999px;
      filter: blur(54px);
      opacity: 0.16;
      pointer-events: none;
      z-index: 0;
      animation: floatBlob 16s ease-in-out infinite;
    }
    body::before {
      top: -120px;
      left: -100px;
      background: rgba(103, 232, 249, 0.45);
    }
    body::after {
      right: -120px;
      bottom: -160px;
      background: rgba(192, 132, 252, 0.4);
      animation-delay: -8s;
    }
    .orb {
      position: fixed;
      width: 320px;
      height: 320px;
      border-radius: 999px;
      filter: blur(48px);
      opacity: 0.12;
      pointer-events: none;
      z-index: 0;
      animation: floatBlob 16s ease-in-out infinite;
    }
    .orb.one {
      top: 30px;
      left: 8%;
      background: rgba(103, 232, 249, 0.35);
    }
    .orb.two {
      right: 5%;
      bottom: 10%;
      background: rgba(192, 132, 252, 0.3);
      animation-delay: -6s;
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
      position: relative;
      overflow: hidden;
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 22px;
      box-shadow: 0 20px 70px rgba(0, 0, 0, 0.35);
      margin-bottom: 16px;
      backdrop-filter: blur(18px);
    }
    .hero::before {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(135deg, rgba(103, 232, 249, 0.08), transparent 32%, rgba(192, 132, 252, 0.06));
      pointer-events: none;
    }
    .hero > * {
      position: relative;
      z-index: 1;
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      padding: 7px 12px;
      border-radius: 999px;
      border: 1px solid rgba(103, 232, 249, 0.18);
      background: rgba(2, 6, 23, 0.35);
      color: #b8f3ff;
      font-size: 0.78rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    .eyebrow .spark {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: linear-gradient(180deg, #7dd3fc, #c084fc);
      box-shadow: 0 0 16px rgba(125, 211, 252, 0.95);
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
      position: relative;
      overflow: hidden;
      backdrop-filter: blur(14px);
      transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.02), 0 16px 40px rgba(0, 0, 0, 0.24);
    }
    .camera-card:hover,
    .action-card:hover {
      transform: translateY(-2px);
      border-color: rgba(103, 232, 249, 0.24);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03), 0 20px 48px rgba(0, 0, 0, 0.28);
    }
    .camera-card::before,
    .action-card::before {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(135deg, rgba(103, 232, 249, 0.05), transparent 34%, rgba(192, 132, 252, 0.04));
      pointer-events: none;
    }
    .section-title {
      font-size: 0.86rem;
      color: var(--muted);
      margin: 0 0 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .square {
      position: relative;
      width: 100%;
      aspect-ratio: 16 / 9;   /* default; overridden by JS once the stream reports its native ratio */
      border-radius: 14px;
      overflow: hidden;
      border: 1px solid var(--line);
      background: radial-gradient(circle at center, rgba(103, 232, 249, 0.08), transparent 35%), #020617;
      box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.02), 0 12px 34px rgba(0, 0, 0, 0.32);
    }
    .square::after {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.06), transparent 18%, transparent 82%, rgba(255, 255, 255, 0.05));
      pointer-events: none;
      animation: scanline 6s ease-in-out infinite;
    }
    video {
      width: 100%;
      height: 100%;
      object-fit: contain;  /* preserve the camera's real aspect ratio, no cropping */
      transform: scaleX(-1);
      filter: contrast(1.05) saturate(1.08);
    }
    .scan-overlay {
      position: absolute;
      inset: 0;
      pointer-events: none;
      background: linear-gradient(180deg, rgba(103, 232, 249, 0.03), transparent 18%, transparent 82%, rgba(192, 132, 252, 0.04));
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
      box-shadow: 0 12px 30px rgba(103, 232, 249, 0.16);
      transition: transform 180ms ease, filter 180ms ease, box-shadow 180ms ease;
    }
    button:hover:not(:disabled) {
      transform: translateY(-1px) scale(1.01);
      filter: brightness(1.04);
      box-shadow: 0 16px 36px rgba(103, 232, 249, 0.24);
    }
    button:disabled {
      cursor: wait;
      opacity: 0.84;
    }
    .status {
      margin-top: 12px;
      border-radius: 12px;
      padding: 12px;
      border: 1px solid var(--line);
      background: rgba(15, 23, 42, 0.92);
      min-height: 78px;
      position: relative;
      overflow: hidden;
      backdrop-filter: blur(12px);
    }
    .status.good { border-color: rgba(74, 222, 128, 0.38); }
    .status.bad { border-color: rgba(248, 113, 113, 0.38); }
    .status.working { border-color: rgba(103, 232, 249, 0.34); }
    .status .label { color: var(--muted); font-size: 0.82rem; margin-bottom: 6px; }
    .status .value { font-size: 1.02rem; font-weight: 700; }
    .status .detail { color: #cbd5e1; margin-top: 4px; line-height: 1.45; font-size: 0.92rem; }
    .status .metric-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    .status .metric {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 10px;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.14);
      background: rgba(2, 6, 23, 0.38);
      color: #dbeafe;
      font-size: 0.82rem;
    }
    .status .metric strong { color: #fff; }
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
      outline: none;
    }
    .alt-card {
      margin-top: 10px;
      padding: 12px 13px;
      border-radius: 12px;
      border: 1px solid rgba(148, 163, 184, 0.12);
      background: rgba(2, 6, 23, 0.38);
    }
    .alt-card .alt-title {
      font-size: 0.94rem;
      font-weight: 700;
      margin-bottom: 4px;
      color: #f8fafc;
    }
    .alt-card .alt-desc {
      color: var(--muted);
      font-size: 0.86rem;
      line-height: 1.5;
    }
    .progress-shell {
      margin-top: 14px;
    }
    .progress-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 8px;
      color: #cbd5e1;
      font-size: 0.86rem;
    }
    .progress-head strong { color: #f8fafc; }
    .progress-track {
      width: 100%;
      height: 12px;
      overflow: hidden;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.16);
      background: rgba(15, 23, 42, 0.7);
    }
    .progress-fill {
      width: 0%;
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, #67e8f9, #c084fc);
      box-shadow: 0 0 18px rgba(103, 232, 249, 0.22);
      transition: width 180ms ease, background 180ms ease;
    }
    .progress-fill.good { background: linear-gradient(90deg, #4ade80, #22c55e); }
    .progress-fill.bad { background: linear-gradient(90deg, #f87171, #fb7185); }
    .progress-fill.working { animation: pulse 1.5s ease-in-out infinite; }
    .progress-meta {
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 8px;
      color: var(--muted);
      font-size: 0.82rem;
    }
    .progress-meta strong { color: #f8fafc; }
    .helper-line {
      color: #9fb1c9;
      font-size: 0.82rem;
      margin-top: 10px;
      line-height: 1.5;
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
    @keyframes floatBlob {
      0%, 100% { transform: translate3d(0, 0, 0) scale(1); }
      50% { transform: translate3d(0, 18px, 0) scale(1.05); }
    }
    @keyframes scanline {
      0%, 100% { transform: translateY(-2%); opacity: 0.55; }
      50% { transform: translateY(2%); opacity: 0.82; }
    }
    @keyframes pulse {
      0%, 100% { filter: brightness(1); }
      50% { filter: brightness(1.12); }
    }
  </style>
</head>
<body>
  <div class="orb one"></div>
  <div class="orb two"></div>

  <main class="shell">
    <div class="topbar">
      <div class="brand"><span class="dot"></span> Phish'N'Chips</div>
      <div>Portal de acesso da equipa</div>
    </div>

    <section class="hero">
      <div class="eyebrow"><span class="spark"></span> Autenticação biométrica com feedback em tempo real</div>
      <h1>Login da equipa Phish'N'Chips</h1>
      <p class="subtitle">
        Posiciona o rosto dentro da câmara e valida o acesso com um clique.
        A validação só passa quando o progresso atinge 100% com confiança acima do threshold.
      </p>
      <div class="badge-row">
        <div class="badge"><span class="chip-dot"></span> Barreira progressiva por percentagem</div>
        <div class="badge"><span class="chip-dot"></span> Efeitos visuais leves e responsivos</div>
        <div class="badge"><span class="chip-dot"></span> Redirecionamento automático quando aprovado</div>
      </div>

      <div class="grid">
        <div class="camera-card">
          <p class="section-title">Câmara</p>
          <div class="square">
            <div class="scan-overlay"></div>
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
          <div id="altDetail" class="alt-card">
            <div class="alt-title">{{ alternativas[0].icone }} {{ alternativas[0].titulo }}</div>
            <div class="alt-desc">{{ alternativas[0].descricao }}</div>
          </div>
          <button id="authBtn">Autenticar</button>
          <button id="demoBtn" type="button" style="margin-top:8px;background:rgba(103,232,249,0.12);color:#67e8f9;border:1px dashed rgba(103,232,249,0.55);cursor:pointer;padding:10px 14px;border-radius:10px;font-weight:600" title="Entrar sem câmara — útil para apresentações remotas">▶ Modo Demo (sem câmara)</button>
          <div id="demoPanel" style="display:none;margin-top:8px;background:rgba(15,23,42,0.6);border:1px solid rgba(148,163,184,0.25);border-radius:10px;padding:10px">
            <div style="font-size:.78rem;color:#94a3b8;margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em">Opção A — Validar imagem real</div>
            <div style="font-size:.78rem;color:#cbd5e1;margin-bottom:6px">Carrega uma foto e ela passa pelo mesmo pipeline de reconhecimento facial:</div>
            <input type="file" id="demoImage" accept="image/*" style="width:100%;padding:6px;border-radius:8px;background:#0f172a;color:#e2e8f0;border:1px solid rgba(148,163,184,0.35);margin-bottom:6px;font-size:.8rem">
            <button id="demoImageGoBtn" type="button" style="width:100%;background:#67e8f9;color:#0f172a;border:0;padding:9px;border-radius:8px;font-weight:700;cursor:pointer;margin-bottom:12px">Validar imagem</button>
            <div id="demoImageStatus" style="font-size:.78rem;color:#94a3b8;margin-bottom:12px;min-height:1em"></div>

            <div style="border-top:1px dashed rgba(148,163,184,0.25);padding-top:10px">
              <div style="font-size:.78rem;color:#94a3b8;margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em">Opção B — Bypass rápido</div>
              <div style="font-size:.78rem;color:#cbd5e1;margin-bottom:6px">Escolhe um utilizador permitido (sem validação):</div>
              <select id="demoUser" style="width:100%;padding:8px;border-radius:8px;background:#0f172a;color:#e2e8f0;border:1px solid rgba(148,163,184,0.35);margin-bottom:8px"></select>
              <button id="demoGoBtn" type="button" style="width:100%;background:rgba(103,232,249,0.18);color:#67e8f9;border:1px solid rgba(103,232,249,0.45);padding:9px;border-radius:8px;font-weight:600;cursor:pointer">Entrar como este utilizador</button>
            </div>
          </div>
          <div class="progress-shell">
            <div class="progress-head">
              <strong>Progresso da verificação</strong>
              <span id="progressText">0.0%</span>
            </div>
            <div class="progress-track" aria-hidden="true">
              <div id="progressFill" class="progress-fill"></div>
            </div>
            <div class="progress-meta">
              <span id="progressHint">Mantém a face estável e acima do threshold.</span>
              <span id="scoreHint">Progresso: 0%</span>
            </div>
          </div>
          <div id="status" class="status">
            <div class="label">Estado</div>
            <div class="value">Pronto para autenticar</div>
            <div class="detail">Clica em “Autenticar” e mantém o rosto dentro da câmara.</div>
            <div class="metric-row">
              <span class="metric"><strong>Objetivo:</strong> atingir 100% da barra</span>
              <span class="metric"><strong>Modo:</strong> progressivo</span>
            </div>
          </div>
          <p class="tip">Se a câmara não iniciar, aceita a permissão do navegador e atualiza a página. Durante a validação, a barra só enche se o score continuar acima do threshold.</p>
        </div>
      </div>
    </section>
  </main>

  <script>
    const video = document.getElementById('camera');
    const authBtn = document.getElementById('authBtn');
    const statusBox = document.getElementById('status');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const progressHint = document.getElementById('progressHint');
    const scoreHint = document.getElementById('scoreHint');
    const alternativaSelect = document.getElementById('alternativa');
    const altDetail = document.getElementById('altDetail');
    const alternatives = {{ alternativas|tojson }};
    const alternativeMap = Object.fromEntries(alternatives.map(alt => [alt.codigo, alt]));
    const REQUIRED_SECONDS = 3.0;
    const SAMPLE_DELAY_MS = 320;
    const MAX_ATTEMPT_SECONDS = 8.0;
    let authInFlight = false;
    let currentScoreText = '--';
    let currentThresholdText = '--';

    const reasonMap = {
      ok: 'OK',
      abaixo_threshold: 'Abaixo do threshold',
      sem_rosto: 'Sem rosto detectado',
      base_vazia: 'Base de dados vazia',
      imagem_invalida: 'Imagem inválida',
      dependencia_ausente: 'Dependência em falta',
      erro_http: 'Erro HTTP',
      erro_interno: 'Erro interno na alternativa'
    };

    function clamp(value, min, max) {
      return Math.min(max, Math.max(min, value));
    }

    function safeNumber(value) {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : null;
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function formatSeconds(ms) {
      return (ms / 1000).toFixed(1);
    }

    function formatPercent(ratio) {
      return (clamp(ratio, 0, 1) * 100).toFixed(1) + '%';
    }

    function formatScore(score) {
      return score === null ? '--' : Number(score).toFixed(3);
    }

    function currentAlternative() {
      if (alternativaSelect && alternativeMap[alternativaSelect.value]) {
        return alternativeMap[alternativaSelect.value];
      }
      return alternatives[0] || null;
    }

    function updateAlternativeCard() {
      if (!altDetail) {
        return;
      }

      const alt = currentAlternative();
      if (!alt) {
        altDetail.innerHTML = '<div class="alt-title">🔐 Alternativa</div><div class="alt-desc">Sem alternativas disponíveis.</div>';
        return;
      }

      altDetail.innerHTML =
        '<div class="alt-title">' + escapeHtml((alt.icone || '🔐') + ' ' + (alt.titulo || alt.codigo || 'Alternativa')) + '</div>' +
        '<div class="alt-desc">' + escapeHtml(alt.descricao || 'Autenticação pronta para validação.') + '</div>';
    }

    function setProgress(ratio, tone, progressLabel, hintLabel) {
      const normalized = clamp(ratio, 0, 1);
      progressFill.style.width = (normalized * 100).toFixed(1) + '%';
      progressFill.className = 'progress-fill ' + tone;
      progressText.textContent = progressLabel || formatPercent(normalized);
      progressHint.textContent = hintLabel;
      scoreHint.textContent = 'Progresso: ' + formatPercent(normalized);
    }

    function renderStatus({ tone, value, detail, metrics = [] }) {
      statusBox.className = 'status ' + tone;
      const metricsHtml = metrics.length
        ? '<div class="metric-row">' + metrics.map(item => '<span class="metric">' + item + '</span>').join('') + '</div>'
        : '';
      statusBox.innerHTML =
        '<div class="label">Estado</div>' +
        '<div class="value">' + value + '</div>' +
        '<div class="detail">' + detail + '</div>' +
        metricsHtml;
    }

    async function startCamera() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'user' },
          audio: false
        });
        video.srcObject = stream;
        // Ajusta o container à razão real da câmara (evita letterbox/cropping)
        video.addEventListener('loadedmetadata', () => {
          if (video.videoWidth && video.videoHeight) {
            const container = video.closest('.square');
            if (container) {
              container.style.aspectRatio = `${video.videoWidth} / ${video.videoHeight}`;
            }
          }
        }, { once: true });
      } catch (err) {
        renderStatus({
          tone: 'bad',
          value: 'Sem acesso à câmara',
          detail: 'Aceita a permissão da câmara no navegador e recarrega a página.',
          metrics: []
        });
        console.error(err);
      }
    }

    async function wait(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }

    async function autenticarFrame() {
      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.92));
      if (!blob) {
        throw new Error('Não foi possível capturar o frame da câmara');
      }

      const formData = new FormData();
      formData.append('frame', blob, 'frame.jpg');
      if (alternativaSelect) {
        formData.append('alternativa', alternativaSelect.value);
      }

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

      return data;
    }

    async function authenticate() {
      if (authInFlight) {
        return;
      }

      if (!video.videoWidth || !video.videoHeight) {
        renderStatus({
          tone: 'bad',
          value: 'A câmara ainda não está pronta',
          detail: 'Espera alguns segundos ou atualiza a página.',
          metrics: []
        });
        return;
      }

      authInFlight = true;
      authBtn.disabled = true;
      authBtn.textContent = 'A validar...';

      const targetMs = REQUIRED_SECONDS * 1000;
      const maxAttemptMs = MAX_ATTEMPT_SECONDS * 1000;
      let stableMs = 0;
      let elapsedMs = 0;
      let lastSampleAt = performance.now();
      let approved = false;
      let lastData = null;

      currentScoreText = '--';
      currentThresholdText = '--';
      setProgress(0, 'working', '0.0%', 'Mantém o rosto estável para encher a barra.');
      renderStatus({
        tone: 'working',
        value: 'A autenticar...',
        detail: 'Vamos acompanhar a percentagem acumulada acima do threshold.',
        metrics: [
          '<strong>Objetivo:</strong> 100% da barra'
        ]
      });

      try {
        while (elapsedMs < maxAttemptMs) {
          const sampleStartedAt = performance.now();
          const data = await autenticarFrame();
          const sampleEndedAt = performance.now();
          lastData = data;

          const score = safeNumber(data.score);
          const threshold = safeNumber(data.threshold);
          currentScoreText = formatScore(score);
          currentThresholdText = threshold === null ? '--' : threshold.toFixed(3);

          const aboveThreshold = Boolean(data.allowed) && score !== null && threshold !== null && score >= threshold;
          const delta = sampleEndedAt - lastSampleAt;
          lastSampleAt = sampleEndedAt;
          elapsedMs += delta;

          if (aboveThreshold) {
            stableMs += delta;
          } else {
            stableMs = 0;
          }

          const reasonText = reasonMap[data.reason] || (data.reason || '-');
          const matchedName = data.matched_name || 'Utilizador';

          setProgress(
            stableMs / targetMs,
            aboveThreshold ? 'good' : 'working',
            formatPercent(stableMs / targetMs),
            aboveThreshold
              ? 'Score consistente acima do threshold. Mantém a face estável.'
              : 'Score abaixo do threshold. A barra reinicia.'
          );

          renderStatus({
            tone: aboveThreshold ? 'working' : 'bad',
            value: aboveThreshold ? ('A validar ' + escapeHtml(matchedName)) : 'Acesso ainda não confirmado',
            detail: aboveThreshold
              ? ('Score estável acima do threshold. Motivo: ' + reasonText)
              : ('Motivo: ' + reasonText + '. Continua a enquadrar o rosto para aumentar a percentagem.'),
            metrics: [
              '<strong>Score:</strong> ' + currentScoreText,
              '<strong>Threshold:</strong> ' + currentThresholdText,
              '<strong>Rosto:</strong> ' + escapeHtml(matchedName)
            ]
          });

          if (stableMs >= targetMs) {
            approved = true;
            break;
          }

          const sleepMs = Math.max(0, SAMPLE_DELAY_MS - (performance.now() - sampleStartedAt));
          if (elapsedMs + sleepMs > maxAttemptMs) {
            break;
          }
          await wait(sleepMs);
        }

        if (approved && lastData) {
          const matchedName = lastData.matched_name || 'Utilizador';
          const target = lastData.redirect_to || '/welcome';
          currentScoreText = formatScore(safeNumber(lastData.score));
          currentThresholdText = safeNumber(lastData.threshold) === null ? '--' : safeNumber(lastData.threshold).toFixed(3);
          setProgress(1, 'good', '100.0%', 'Threshold mantido durante o período pedido.');
          renderStatus({
            tone: 'good',
            value: 'Pessoa permitida: ' + escapeHtml(matchedName),
            detail: 'A validação chegou a 100% com confiança acima do threshold.',
            metrics: [
              '<strong>Score final:</strong> ' + currentScoreText,
              '<strong>Threshold:</strong> ' + currentThresholdText,
              '<strong>Estado:</strong> aprovado'
            ]
          });

          setTimeout(() => {
            window.location.href = target;
          }, 900);
        } else {
          const reasonText = lastData ? (reasonMap[lastData.reason] || (lastData.reason || '-')) : 'tempo esgotado';
          setProgress(stableMs / targetMs, 'bad', formatPercent(stableMs / targetMs), 'Não foi possível manter o threshold o tempo suficiente.');
          renderStatus({
            tone: 'bad',
            value: 'Acesso negado',
            detail: 'A barra não chegou a 100%. Motivo: ' + reasonText + '.',
            metrics: [
              '<strong>Score final:</strong> ' + currentScoreText,
              '<strong>Threshold:</strong> ' + currentThresholdText,
              '<strong>Progresso máximo:</strong> ' + formatPercent(stableMs / targetMs)
            ]
          });
        }
      } catch (err) {
        const msg = (err && err.message) ? err.message : 'Falha ao autenticar';
        renderStatus({
          tone: 'bad',
          value: 'Erro na validação',
          detail: msg,
          metrics: [
            '<strong>Score:</strong> ' + currentScoreText,
            '<strong>Threshold:</strong> ' + currentThresholdText
          ]
        });
      } finally {
        authInFlight = false;
        authBtn.disabled = false;
        authBtn.textContent = 'Autenticar';
      }
    }

    if (alternativaSelect) {
      alternativaSelect.addEventListener('change', updateAlternativeCard);
    }
    authBtn.addEventListener('click', authenticate);
    updateAlternativeCard();
    startCamera();

    // ── Modo Demo (bypass da câmara para apresentações remotas) ──
    const demoBtn    = document.getElementById('demoBtn');
    const demoPanel  = document.getElementById('demoPanel');
    const demoUser   = document.getElementById('demoUser');
    const demoGoBtn  = document.getElementById('demoGoBtn');
    async function loadDemoUsers() {
      try {
        const r = await fetch('/auth/simulate/users');
        const j = await r.json();
        const users = Array.isArray(j.users) ? j.users : [];
        demoUser.innerHTML = users.length
          ? users.map(u => `<option value="${u}">${u}</option>`).join('')
          : '<option value="">— sem utilizadores —</option>';
      } catch (_) {
        demoUser.innerHTML = '<option value="">— erro a carregar —</option>';
      }
    }
    demoBtn.addEventListener('click', () => {
      const show = demoPanel.style.display === 'none';
      demoPanel.style.display = show ? '' : 'none';
      if (show && !demoUser.options.length) loadDemoUsers();
    });
    demoGoBtn.addEventListener('click', async () => {
      const name = demoUser.value;
      if (!name) return;
      demoGoBtn.disabled = true;
      demoGoBtn.textContent = 'A entrar...';
      try {
        const r = await fetch('/auth/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name }),
        });
        const j = await r.json();
        if (j.allowed && j.redirect_to) {
          window.location.href = j.redirect_to;
        } else {
          demoGoBtn.disabled = false;
          demoGoBtn.textContent = 'Entrar como este utilizador';
          alert(j.error || 'Falha no modo demo');
        }
      } catch (err) {
        demoGoBtn.disabled = false;
        demoGoBtn.textContent = 'Entrar como este utilizador';
        alert('Erro: ' + (err && err.message ? err.message : err));
      }
    });

    // Opção A — valida uma imagem real escolhida pelo utilizador.
    // Reaproveita /auth (mesmo endpoint da câmara) enviando a imagem como
    // o campo "frame" — garante paridade exacta com o fluxo normal.
    const demoImage        = document.getElementById('demoImage');
    const demoImageGoBtn   = document.getElementById('demoImageGoBtn');
    const demoImageStatus  = document.getElementById('demoImageStatus');
    demoImageGoBtn.addEventListener('click', async () => {
      const file = demoImage.files && demoImage.files[0];
      if (!file) {
        demoImageStatus.textContent = 'Escolhe uma imagem primeiro.';
        demoImageStatus.style.color = '#fca5a5';
        return;
      }
      demoImageGoBtn.disabled = true;
      demoImageGoBtn.textContent = 'A validar...';
      demoImageStatus.textContent = 'A correr reconhecimento facial...';
      demoImageStatus.style.color = '#94a3b8';
      try {
        const formData = new FormData();
        formData.append('frame', file, file.name || 'demo.jpg');
        if (alternativaSelect) formData.append('alternativa', alternativaSelect.value);
        const r = await fetch('/auth', { method: 'POST', body: formData });
        const j = await r.json();
        if (j.allowed && j.redirect_to) {
          demoImageStatus.style.color = '#86efac';
          demoImageStatus.textContent = `✓ ${j.matched_name} (score ${typeof j.score === 'number' ? j.score.toFixed(3) : '?'})`;
          setTimeout(() => { window.location.href = j.redirect_to; }, 600);
        } else {
          demoImageStatus.style.color = '#fca5a5';
          const reason = j.error || j.reason || 'Imagem não reconhecida';
          const score  = typeof j.score === 'number' ? ` (score ${j.score.toFixed(3)})` : '';
          demoImageStatus.textContent = `✗ ${reason}${score}`;
          demoImageGoBtn.disabled = false;
          demoImageGoBtn.textContent = 'Validar imagem';
        }
      } catch (err) {
        demoImageStatus.style.color = '#fca5a5';
        demoImageStatus.textContent = 'Erro: ' + (err && err.message ? err.message : err);
        demoImageGoBtn.disabled = false;
        demoImageGoBtn.textContent = 'Validar imagem';
      }
    });
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
    :root {
      --text: #e2e8f0;
      --muted: #94a3b8;
    }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at top left, rgba(103, 232, 249, 0.12), transparent 30%),
        radial-gradient(circle at top right, rgba(192, 132, 252, 0.14), transparent 26%),
        linear-gradient(135deg, #020617, #0f172a 55%, #111827);
      color: var(--text);
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      padding: 24px;
      overflow: hidden;
    }
    .card {
      width: min(680px, 100%);
      position: relative;
      border-radius: 24px;
      border: 1px solid rgba(148, 163, 184, 0.2);
      background: rgba(15, 23, 42, 0.84);
      box-shadow: 0 28px 90px rgba(0, 0, 0, 0.4);
      backdrop-filter: blur(18px);
      padding: 32px;
      text-align: center;
    }
    .card::before {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(135deg, rgba(103, 232, 249, 0.08), transparent 32%, rgba(192, 132, 252, 0.06));
      border-radius: inherit;
      pointer-events: none;
    }
    .card > * {
      position: relative;
      z-index: 1;
    }
    .kicker {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: #38bdf8;
      margin-bottom: 12px;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid rgba(56, 189, 248, 0.16);
      background: rgba(2, 6, 23, 0.34);
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
      box-shadow: 0 12px 30px rgba(103, 232, 249, 0.18);
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
            meta = None
        alternativas.append(
            {
                "codigo": codigo,
                "label": label,
                "descricao": getattr(meta, "descricao", ""),
                "titulo": getattr(meta, "titulo", codigo),
                "icone": getattr(meta, "icone", "🔐"),
            }
        )

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
        resultado["redirect_to"] = url_for("dashboard")
    return jsonify(resultado)


# ── Demo / simulação de login (sem câmara) ──
# Útil para apresentações remotas ou ambientes sem webcam. Aceita apenas
# nomes que existam em frontend/pessoas_permitidas/ para manter paridade com
# o fluxo real (o dashboard recebe o mesmo tipo de session["auth_name"]).
def _listar_pessoas_permitidas() -> list[str]:
    base = Path(__file__).parent / "pessoas_permitidas"
    if not base.exists():
        return []
    return sorted([p.name for p in base.iterdir() if p.is_dir() and not p.name.startswith(".")])


@app.get("/auth/simulate/users")
def auth_simulate_users():
    return jsonify({"users": _listar_pessoas_permitidas()})


@app.post("/auth/simulate")
def auth_simulate():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"allowed": False, "error": "nome ausente"}), 400
    permitidos = _listar_pessoas_permitidas()
    if name not in permitidos:
        return jsonify({"allowed": False, "error": f"utilizador '{name}' não está na lista de permitidos"}), 403
    session["auth_name"] = name
    session["auth_demo"] = True  # marca a sessão como simulada (não passou pela câmara)
    return jsonify({
        "allowed": True,
        "matched_name": name,
        "demo": True,
        "redirect_to": url_for("dashboard"),
    })


@app.get("/welcome")
def welcome():
    nome = session.get("auth_name")
    if not nome:
        return redirect(url_for("home"))
    return render_template_string(WELCOME_HTML, nome=nome)


@app.get("/dashboard")
def dashboard():
    nome = session.get("auth_name")
    if not nome:
        return redirect(url_for("home"))
    resp = app.make_response(render_template("dashboard.html", nome=nome, ollama_model=OLLAMA_MODEL))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.get("/dualsentinel")
def dualsentinel_page():
    nome = session.get("auth_name")
    if not nome:
        return redirect(url_for("home"))
    resp = app.make_response(render_template("dualsentinel.html", nome=nome))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.post("/logout")
def logout():
    session.pop("auth_name", None)
    return redirect(url_for("home"))


# ── Detection API ─────────────────────────────────────────────────────────────

@app.get("/api/ollama_status")
def api_ollama_status():
    available, models = _ds.check_ollama(OLLAMA_BASE_URL, OLLAMA_MODEL)
    return jsonify({"available": available, "model": OLLAMA_MODEL, "installed": models})


@app.get("/api/threats")
def api_threats():
    source = request.args.get("source", "OTRF Atomic Red Team")
    limit  = int(request.args.get("limit", 20))
    try:
        chains = _ds.get_flagged_chains(source, limit=limit)
        return jsonify(chains)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@app.post("/api/threats/<int:chain_id>/windows")
def api_windows(chain_id: int):
    body          = request.get_json(force=True)
    chain_indices = body.get("chain_indices", [])
    if not chain_indices:
        return jsonify({"error": "chain_indices required"}), 400
    try:
        windows = _ds.score_all_windows(chain_indices)
        return jsonify(windows)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@app.post("/api/threats/<int:chain_id>/score")
def api_score(chain_id: int):
    body          = request.get_json(force=True)
    chain_indices = body.get("chain_indices", [])
    if not chain_indices:
        return jsonify({"error": "chain_indices required"}), 400
    try:
        events = _ds.score_chain_events(chain_indices)
        return jsonify(events)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


@app.post("/api/threats/<int:chain_id>/attribute")
def api_attribute(chain_id: int):
    body          = request.get_json(force=True)
    chain_indices = body.get("chain_indices", [])
    ollama_model  = body.get("ollama_model", OLLAMA_MODEL).strip() or OLLAMA_MODEL
    if not chain_indices:
        return jsonify({"error": "chain_indices required"}), 400
    try:
        result = _ds.attribute_chain(
            chain_indices,
            ollama_model=ollama_model,
            ollama_base_url=OLLAMA_BASE_URL,
            ollama_timeout=OLLAMA_TIMEOUT,
        )
        return jsonify(result)
    except Exception as exc:
        traceback.print_exc()
        return jsonify({"error": str(exc)}), 500


# ── DualSentinel API ──────────────────────────────────────────────────────────

def _ds2_run_bg(
    run_id: str,
    file_path: Path,
    dataset: str,
    threshold: float,
    skip_judge: bool,
    max_rows: int | None = None,
    max_llm_calls: int | None = None,
    use_kb: bool = True,
    evaluate: bool = False,
    seed: int = 42,
    slm_model: str | None = None,
    judge_model: str | None = None,
) -> None:
    """Background thread: run DualSentinel pipeline and store result in _ds2_runs."""
    with _ds2_lock:
        _ds2_runs[run_id]["status"]   = "running"
        _ds2_runs[run_id]["message"]  = "A iniciar pipeline..."
        _ds2_runs[run_id]["stage"]    = "init"
        _ds2_runs[run_id]["progress"] = 0.0
    try:
        from pipeline import run_pipeline  # imported here to avoid module-level side effects
        output_dir = Path(__file__).resolve().parent.parent / "DualSentinel" / "results"

        # Progress callback bridges pipeline's per-stage updates into _ds2_runs,
        # so the /api/dualsentinel/status endpoint can stream them to the UI.
        def _on_progress(ev: dict) -> None:
            with _ds2_lock:
                run = _ds2_runs.get(run_id)
                if run is None:
                    return
                run["message"]  = ev.get("message", run.get("message", ""))
                run["stage"]    = ev.get("stage", run.get("stage", ""))
                run["progress"] = ev.get("progress", run.get("progress", 0.0))
                # pass through any extra fields (flagged, targets, sub_i, sub_n…)
                for k, v in ev.items():
                    if k not in {"message", "stage", "progress"}:
                        run[k] = v

        result = run_pipeline(
            input_path=file_path,
            dataset=dataset,
            output_dir=output_dir / run_id,
            threshold=threshold,
            skip_judge=skip_judge,
            max_rows=max_rows,
            max_llm_calls=max_llm_calls,
            use_kb=use_kb,
            evaluate=evaluate,
            seed=seed,
            progress_cb=_on_progress,
            slm_model=slm_model,
            judge_model=judge_model,
        )
        with _ds2_lock:
            _ds2_runs[run_id]["status"]   = "done"
            _ds2_runs[run_id]["message"]  = "Pipeline concluído."
            _ds2_runs[run_id]["stage"]    = "done"
            _ds2_runs[run_id]["progress"] = 1.0
            _ds2_runs[run_id]["result"]   = result
    except Exception as exc:
        traceback.print_exc()
        with _ds2_lock:
            _ds2_runs[run_id]["status"]  = "error"
            _ds2_runs[run_id]["message"] = str(exc)
            _ds2_runs[run_id]["stage"]   = "error"
            _ds2_runs[run_id]["error"]   = str(exc)


@app.get("/api/dualsentinel/samples")
def api_ds2_samples():
    """List available sample files under DualSentinel/data/samples/."""
    if not _DS_SAMPLES.exists():
        return jsonify([])
    exts = {".csv", ".log", ".xml", ".evtx"}
    files = []
    for p in sorted(_DS_SAMPLES.rglob("*")):
        if p.suffix.lower() in exts and p.is_file():
            files.append({
                "name":     p.name,
                "rel_path": str(p.relative_to(_DS_SAMPLES)).replace("\\", "/"),
                "size_kb":  round(p.stat().st_size / 1024, 1),
            })
    return jsonify(files)


@app.post("/api/dualsentinel/run")
def api_ds2_run():
    """Launch a DualSentinel pipeline run in a background thread."""
    body      = request.get_json(force=True)
    rel_file  = (body.get("file") or "").strip()
    dataset   = (body.get("dataset") or "lmd").strip().lower()
    threshold = float(body.get("threshold") or 0.6)
    skip_judge = bool(body.get("skip_judge", False))
    max_rows_raw = body.get("max_rows")
    max_rows: int | None = int(max_rows_raw) if max_rows_raw else None
    max_llm_calls_raw = body.get("max_llm_calls")
    max_llm_calls: int | None = int(max_llm_calls_raw) if max_llm_calls_raw else None
    use_kb     = bool(body.get("use_kb", True))
    evaluate   = bool(body.get("evaluate", False))
    seed       = int(body.get("seed") or 42)
    # Optional per-run model overrides (UI dropdowns). None → fall back to .env.
    slm_model   = (body.get("slm_model")   or "").strip() or None
    judge_model = (body.get("judge_model") or "").strip() or None

    if not rel_file:
        return jsonify({"error": "file is required"}), 400

    # Path traversal guard — resolve and check it stays under _DS_SAMPLES
    try:
        file_path = (_DS_SAMPLES / rel_file).resolve()
        _DS_SAMPLES.resolve()  # ensure base exists
        file_path.relative_to(_DS_SAMPLES.resolve())  # raises if outside
    except (ValueError, OSError):
        return jsonify({"error": "Invalid file path"}), 400

    if not file_path.exists():
        return jsonify({"error": f"File not found: {rel_file}"}), 404

    run_id = str(uuid.uuid4())
    with _ds2_lock:
        _ds2_runs[run_id] = {
            "status": "queued", "message": "Na fila de espera...",
            "stage": "queued", "progress": 0.0,
            "result": None, "error": None,
        }

    t = threading.Thread(
        target=_ds2_run_bg,
        args=(run_id, file_path, dataset, threshold, skip_judge, max_rows,
              max_llm_calls, use_kb, evaluate, seed, slm_model, judge_model),
        daemon=True,
        name=f"ds2-{run_id[:8]}",
    )
    t.start()
    return jsonify({"run_id": run_id})


@app.get("/api/dualsentinel/status/<run_id>")
def api_ds2_status(run_id: str):
    with _ds2_lock:
        run = _ds2_runs.get(run_id)
    if run is None:
        return jsonify({"error": "Run not found"}), 404
    # Echo all non-heavy fields so the UI can display rich progress
    # (stage, percentage, sub-window counters, model in use, …).
    payload = {k: v for k, v in run.items() if k not in {"result"}}
    return jsonify(payload)


@app.get("/api/dualsentinel/results/<run_id>")
def api_ds2_results(run_id: str):
    with _ds2_lock:
        run = _ds2_runs.get(run_id)
    if run is None:
        return jsonify({"error": "Run not found"}), 404
    if run["status"] == "running" or run["status"] == "queued":
        return jsonify({"error": "Still running", "status": run["status"]}), 409
    if run["status"] == "error":
        return jsonify({"error": run["error"]}), 500
    result = run["result"] or {}

    # Coerce numpy scalars / arrays to native Python types for JSON encoding.
    def _coerce(o):
        import numpy as _np
        if isinstance(o, dict):
            return {k: _coerce(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [_coerce(v) for v in o]
        if isinstance(o, _np.generic):
            return o.item()
        if isinstance(o, _np.ndarray):
            return _coerce(o.tolist())
        return o

    # Read sidecar artefacts (metrics / telemetry / manifest) if produced
    out_dir = Path(result.get("output_dir", "")) if result.get("output_dir") else None
    sidecars: dict = {}
    if out_dir and out_dir.exists():
        for key, fname in (("metrics", "metrics.json"),
                           ("telemetry", "telemetry.json"),
                           ("manifest", "run_manifest.json")):
            fp = out_dir / fname
            if fp.exists():
                try:
                    sidecars[key] = json.loads(fp.read_text(encoding="utf-8"))
                except Exception:
                    sidecars[key] = None

    return jsonify(_coerce({
        "windows":       result.get("windows", []),
        "judge_results": result.get("judge_results", []),
        "output_dir":    result.get("output_dir", ""),
        "report":        result.get("report", ""),
        "metrics":       sidecars.get("metrics"),
        "telemetry":     sidecars.get("telemetry"),
        "manifest":      sidecars.get("manifest"),
    }))


# ── DualSentinel: health, history, persisted-results helpers ──────────────────

_DS2_RESULTS_DIR = Path(__file__).resolve().parent.parent / "DualSentinel" / "results"


def _ds2_run_summary(run_dir: Path) -> dict | None:
    """Inspect a results/<run_id>/ folder and produce a compact summary."""
    if not run_dir.is_dir():
        return None
    manifest_fp = run_dir / "run_manifest.json"
    judge_fp    = run_dir / "judge_results.json"
    windows_fp  = run_dir / "windows_scored.json"
    metrics_fp  = run_dir / "metrics.json"
    summary: dict = {
        "run_id":      run_dir.name,
        "timestamp":   "",
        "windows":     None,
        "judged":      0,
        "has_metrics": metrics_fp.exists(),
    }
    if manifest_fp.exists():
        try:
            mf = json.loads(manifest_fp.read_text(encoding="utf-8"))
            summary["timestamp"] = mf.get("timestamp") or mf.get("started_at") or ""
        except Exception:
            pass
    if not summary["timestamp"]:
        try:
            from datetime import datetime
            summary["timestamp"] = datetime.fromtimestamp(run_dir.stat().st_mtime).isoformat()
        except Exception:
            pass
    if windows_fp.exists():
        try:
            summary["windows"] = len(json.loads(windows_fp.read_text(encoding="utf-8")))
        except Exception:
            pass
    if judge_fp.exists():
        try:
            summary["judged"] = len(json.loads(judge_fp.read_text(encoding="utf-8")))
        except Exception:
            pass
    return summary


@app.get("/api/dualsentinel/health")
def api_ds2_health():
    """DualSentinel-specific health: Ollama up, models pulled, KB ready, last run."""
    slm_model   = os.getenv("SLM_MODEL",   "phi3:medium")
    judge_model = os.getenv("JUDGE_MODEL", "llama3.2")

    ollama_up = False
    installed: list = []
    try:
        ollama_up, installed = _ds.check_ollama(OLLAMA_BASE_URL, slm_model)
    except Exception:
        pass

    # check_ollama returns the bare model names; tag-stripped match is enough
    def _has(model: str) -> bool:
        if not installed:
            return False
        base = model.split(":")[0].lower()
        return any(base == (m or "").split(":")[0].lower() for m in installed)

    # KB
    kb_ready = False
    kb_count: int | None = None
    try:
        sys.path.insert(0, str(_DS_ROOT))
        import attack_kb as _kb  # noqa: E402
        kb_ready = _kb.is_available()
        if kb_ready:
            try:
                vs = _kb._load_vector_store()  # noqa: SLF001
                if vs is not None:
                    kb_count = vs.get_collection().count()
            except Exception:
                pass
    except Exception:
        pass

    # Last run
    last_run = None
    if _DS2_RESULTS_DIR.exists():
        runs = [p for p in _DS2_RESULTS_DIR.iterdir() if p.is_dir()]
        if runs:
            latest = max(runs, key=lambda p: p.stat().st_mtime)
            last_run = _ds2_run_summary(latest)

    return jsonify({
        "ollama_up":       ollama_up,
        "ollama_url":      OLLAMA_BASE_URL,
        "slm_model":       slm_model,
        "slm_available":   ollama_up and _has(slm_model),
        "judge_model":     judge_model,
        "judge_available": ollama_up and _has(judge_model),
        "installed_models": installed,  # list of Ollama models for the UI dropdowns
        "kb_ready":        kb_ready,
        "kb_techniques":   kb_count,
        "last_run":        last_run,
    })


@app.get("/api/dualsentinel/history")
def api_ds2_history():
    """List historical DualSentinel runs persisted under DualSentinel/results/."""
    if not _DS2_RESULTS_DIR.exists():
        return jsonify([])
    runs = []
    for p in sorted(_DS2_RESULTS_DIR.iterdir(), key=lambda d: d.stat().st_mtime, reverse=True):
        s = _ds2_run_summary(p)
        if s is not None:
            runs.append(s)
    return jsonify(runs[:50])


@app.get("/api/dualsentinel/history/<run_id>")
def api_ds2_history_run(run_id: str):
    """Load a persisted run from disk by its directory name."""
    if "/" in run_id or "\\" in run_id or run_id.startswith("."):
        return jsonify({"error": "Invalid run_id"}), 400
    run_dir = (_DS2_RESULTS_DIR / run_id).resolve()
    try:
        run_dir.relative_to(_DS2_RESULTS_DIR.resolve())
    except ValueError:
        return jsonify({"error": "Invalid run_id"}), 400
    if not run_dir.is_dir():
        return jsonify({"error": "Run not found"}), 404

    def _load(name: str):
        fp = run_dir / name
        if not fp.exists():
            return None
        try:
            return json.loads(fp.read_text(encoding="utf-8"))
        except Exception:
            return None

    return jsonify({
        "windows":       _load("windows_scored.json") or [],
        "judge_results": _load("judge_results.json")  or [],
        "metrics":       _load("metrics.json"),
        "telemetry":     _load("telemetry.json"),
        "manifest":      _load("run_manifest.json"),
        "output_dir":    str(run_dir),
        "report":        "",
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=_env_bool("FRONTEND_DEBUG", False),
        use_reloader=_env_bool("FRONTEND_RELOADER", False),
    )

