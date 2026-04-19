# Cores do Frontend — Phish'N'Chips

## Variáveis CSS (tokens globais)

| Token | Valor | Uso |
|---|---|---|
| `--bg` | `#07131f` | Background principal da página |
| `--card` | `rgba(15, 23, 42, 0.9)` | Fundo dos cards / painéis |
| `--line` | `rgba(148, 163, 184, 0.2)` | Bordas visíveis |
| `--line-soft` | `rgba(148, 163, 184, 0.12)` | Bordas subtis / separadores |
| `--text` | `#e2e8f0` | Texto principal |
| `--muted` | `#94a3b8` | Texto secundário / labels |
| `--accent` | `#67e8f9` | Cor de destaque (ciano) |
| `--ok` | `#4ade80` | Estado OK / sucesso (só no login) |
| `--bad` | `#f87171` | Estado de erro / negado (só no login) |

---

## Backgrounds

| Cor | Uso |
|---|---|
| `#07131f` | Background global (`--bg`) |
| `#020617` | Background profundo (câmara, deep layers) |
| `#0f172a` | Welcome page card |
| `#111827` | Gradiente welcome page (3.º stop) |
| `#03111d` | Gradiente background (1.º stop) |
| `#10223a` | Gradiente background (3.º stop) |
| `rgba(7, 19, 31, 0.85)` | Topbar do dashboard |
| `rgba(2, 6, 23, 0.3)` | Queue panel / statusbar |
| `rgba(2, 6, 23, 0.34–0.45)` | Chips internos / badges / alt-card |
| `rgba(2, 6, 23, 0.5)` | Attribution result box |
| `rgba(2, 6, 23, 0.7)` | Dropdowns / inputs |
| `rgba(15, 23, 42, 0.5)` | Chain item normal |
| `rgba(15, 23, 42, 0.7)` | Progress track |
| `rgba(15, 23, 42, 0.84)` | Welcome card |
| `rgba(15, 23, 42, 0.85)` | Chain item ativo |
| `rgba(15, 23, 42, 0.92)` | Status box no login |

### Gradientes de Background

| Gradiente | Uso |
|---|---|
| `linear-gradient(135deg, #03111d, #07131f 55%, #10223a)` | Body login + dashboard |
| `linear-gradient(135deg, #020617, #0f172a 55%, #111827)` | Welcome page body |
| `linear-gradient(135deg, rgba(103,232,249,0.08), transparent 32%, rgba(192,132,252,0.06))` | Overlay decorativo hero / section-card |
| `linear-gradient(135deg, rgba(103,232,249,0.05), transparent 34%, rgba(192,132,252,0.04))` | Overlay decorativo camera/action cards |
| `radial-gradient(circle at center, rgba(103,232,249,0.08), transparent 35%), #020617` | Fundo quadrado câmara |
| `radial-gradient(circle at top left, rgba(103,232,249,0.12), transparent 30%)` | Decorativo welcome page |
| `radial-gradient(circle at top right, rgba(192,132,252,0.14), transparent 26%)` | Decorativo welcome page |

---

## Texto

| Cor | Uso |
|---|---|
| `#e2e8f0` | Texto principal (`--text`) |
| `#f8fafc` | Valores de destaque / stat boxes / strong |
| `#fff` | `strong` dentro de `.metric` |
| `#94a3b8` | Labels / legendas (`--muted`) |
| `#cbd5e1` | Detalhe / progress meta / score numbers |
| `#9fb1c9` | Helper lines no login |
| `#dbeafe` | Metrics no login |
| `#b8f3ff` | Eyebrow label / EID chips |
| `#020617` | Texto sobre botões (contraste escuro) |

---

## Cor de Destaque — Ciano / Accent

| Cor | Uso |
|---|---|
| `#67e8f9` | `--accent`; progress fill padrão |
| `#7dd3fc` | Gradiente botões (início); image cells; chain-images |
| `#38bdf8` | Kicker do welcome page |
| `rgba(103, 232, 249, 0.*)` | Bordas hover, overlays, glows, spinners |
| `rgba(125, 211, 252, 0.*)` | Glow da `.dot` e `.spark` |

---

## Cor Roxa / Violeta

| Cor | Uso |
|---|---|
| `#c084fc` | Gradiente botões (fim) |
| `rgba(192, 132, 252, 0.*)` | Blobs decorativos (orb), overlays |
| `#e9d5ff` | Texto RAG chips |
| `rgba(192, 132, 252, 0.12–0.2)` | Background e border RAG chips |

---

## Cor Rosa

| Cor | Uso |
|---|---|
| `#f9a8d4` | 3.º stop gradiente h1 welcome page |

---

## Estados de Score / Semáforo

### Vermelho — Score Alto (ameaça alta)

| Cor | Uso |
|---|---|
| `#f87171` | `--bad`; border `.status.bad`; `.progress-fill.bad` |
| `#fb7185` | Gradiente `.progress-fill.bad` (fim) |
| `#fca5a5` | Texto `.score-high` / `.conf-high` |
| `rgba(248, 113, 113, 0.18)` | Background `.score-high` / `.conf-high` |
| `rgba(248, 113, 113, 0.3)` | Border `.score-high` |
| `rgba(248, 113, 113, 0.38)` | Border `.status.bad` |

### Amarelo — Score Médio (suspeito)

| Cor | Uso |
|---|---|
| `#fbbf24` | LED amarelo (Ollama offline) |
| `#fde68a` | Texto `.score-medium` / `.conf-medium` |
| `rgba(251, 191, 36, 0.15)` | Background `.score-medium` / `.conf-medium` |
| `rgba(251, 191, 36, 0.25)` | Border `.score-medium` |

### Verde — Score Baixo (normal / OK)

| Cor | Uso |
|---|---|
| `#4ade80` | `--ok`; LED verde; `.progress-fill.good` |
| `#22c55e` | Gradiente `.progress-fill.good` (fim); window bars |
| `#86efac` | Texto `.score-low` / `.conf-low` |
| `rgba(74, 222, 128, 0.12–0.38)` | Background e border `.score-low`; border `.status.good` |

---

## Confidence Badges (Attribution)

| Classe | Background | Texto |
|---|---|---|
| `.conf-high` | `rgba(248,113,113,0.18)` | `#fca5a5` |
| `.conf-medium` | `rgba(251,191,36,0.15)` | `#fde68a` |
| `.conf-low` | `rgba(74,222,128,0.12)` | `#86efac` |

---

## Sombras e Glows

| Elemento | Sombra |
|---|---|
| Hero card (login) | `0 20px 70px rgba(0,0,0,0.35)` |
| Welcome card | `0 28px 90px rgba(0,0,0,0.4)` |
| Quadrado câmara | `inset 0 0 0 1px rgba(255,255,255,0.02), 0 12px 34px rgba(0,0,0,0.32)` |
| Section card dashboard | `inset 0 1px 0 rgba(255,255,255,0.02), 0 16px 40px rgba(0,0,0,0.2)` |
| Camera/action cards | `inset 0 1px 0 rgba(255,255,255,0.02), 0 16px 40px rgba(0,0,0,0.24)` |
| Botão primário | `0 12px 30px rgba(103,232,249,0.16–0.18)` |
| Botão hover | `0 16px 36px rgba(103,232,249,0.24)` |
| Attribution btn | `0 8px 24px rgba(103,232,249,0.12)` |
| Progress fill glow | `0 0 18px rgba(103,232,249,0.22)` |
| `.dot` (brand) | `0 0 12px rgba(125,211,252,0.9)` |
| `.spark` (eyebrow) | `0 0 16px rgba(125,211,252,0.95)` |
| LED verde | `0 0 8px #4ade80` |
| LED amarelo | `0 0 8px #fbbf24` |

---

## Gradientes dos Botões e UI

```css
/* Botões primários (autenticar, logout, attr-btn) */
background: linear-gradient(90deg, #7dd3fc, #c084fc);

/* h1 welcome page (texto clip) */
background: linear-gradient(90deg, #7dd3fc, #c084fc, #f9a8d4);

/* .spark (eyebrow badge) */
background: linear-gradient(180deg, #7dd3fc, #c084fc);

/* Progress fill padrão */
background: linear-gradient(90deg, #67e8f9, #c084fc);

/* Progress fill OK */
background: linear-gradient(90deg, #4ade80, #22c55e);

/* Progress fill Bad */
background: linear-gradient(90deg, #f87171, #fb7185);