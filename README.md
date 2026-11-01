<div align="center">

# 🛡️ Sentinel-Graph (SOC v2)

### Multimodal AI-Assisted Phishing & Threat Intelligence Detection

![Tests](https://img.shields.io/badge/tests-371%20passed%20(local)-00ff66?style=for-the-badge&logo=pytest&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-2.14-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![ONNX Runtime](https://img.shields.io/badge/ONNX%20Runtime-1.31-005CED?style=for-the-badge&logo=onnx&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-WebSockets-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Three.js](https://img.shields.io/badge/Three.js-WebGL-000000?style=for-the-badge&logo=threedotjs&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**B.Sc. Cyber and Digital Science (SYBSc CDS) — Capstone Project**<br/>
Developed by **Uday Babasaheb Baviskar** · Suryadatta International Institute of Cyber Security (SIICS), Pune · Savitribai Phule Pune University

</div>

---

## 🚀 Quick Start (Fresh Clone)

Needs **64-bit Python 3.12–3.14** (3.15 is too new: the pinned onnxruntime, numpy and scikit-learn have no wheels for it yet) and **Node.js 20.19+ or 22.12+** (Vite 8). A git clone or a GitHub ZIP download both work. From the repository root, run the setup script once; it checks both versions, installs the pip packages, Playwright Chromium and the frontend `node_modules`, and checks that the backend imports:

```bat
setup.bat
```

```bash
bash setup.sh
```

(`setup.bat` on Windows, `bash setup.sh` on macOS/Linux.) On Windows, setup falls back to other installed Pythons (via the `py` launcher, Anaconda or Miniconda) when `python` is unsuitable, and records the one it used in `.sentinel-python`; pass a path to choose one yourself: `setup.bat C:\Users\you\anaconda3\python.exe`. Then start everything with one command; it runs the frontend and the backend with the same Python, opens the browser once the models have loaded (about 30 s), and **Ctrl-C** (or closing the window) stops both:

```bat
run.bat
```

Or start the two halves yourself, in two terminals, with the Python setup installed into:

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

```bash
cd frontend
npm run dev -- --port 5173 --strictPort
```

Keep `--strictPort`: if 5173 is taken, Vite would quietly move to 5174, and the backend refuses WebSocket connections from any origin but `localhost:5173` and `127.0.0.1:5173`, so every scan would fail.

**If it does not start (Windows):**

- *"Could not open the browser automatically"*: the servers are running; open http://localhost:5173 yourself. The PC's default-browser setting is broken (Settings → Apps → Default apps).
- *"Port 5173 (or 8000) is already in use by …"*: close that program; if it is an earlier `run.bat`, close its window or run the `taskkill` command the message prints.
- *`DLL load failed` from torch or onnxruntime*: install the [Microsoft Visual C++ Redistributable (x64)](https://aka.ms/vs/17/release/vc_redist.x64.exe) and run `setup.bat` again.
- *pip fails on a long file path*: enable Windows long paths (the python.org installer's "Disable path length limit" button), then run `setup.bat` again.
- *EPERM / EBUSY from npm, or "database is locked"*: the folder is probably synced by OneDrive, which locks files mid-write; move it out (for example to `C:\sentinel-graph`).
- Logs: the backend prints in the `run.bat` window; the frontend writes to `%TEMP%\sentinel-graph-local\frontend.log`.

Open **http://localhost:5173** and drop one of the `.eml` files from `samples/`. The trained production models ship in the repository (`models/fusion_meta.joblib` — the 12-feature fusion model, OOF ROC-AUC 0.953 — and `models/topology/memae.pt`, about 670 KB in plain git, no Git LFS needed), so the samples score as documented in `samples/README.txt`. The vision and SLM engines are still stand-ins (see the model status table below).

### 🌐 Host it publicly (Cloudflare quick tunnel, Windows)

Needs [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) on `PATH` (`winget install --id Cloudflare.cloudflared`). Stop any dev server on ports 5173 and 8000 first, then:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\host_tunnel.ps1
```

The script builds the frontend, serves the production build with `vite preview` on :5173 (the dev server is too slow through a tunnel), opens the tunnel, and starts the backend with the tunnel's `https://<words>.trycloudflare.com` address added to `SOC_CORS_ALLOW_ORIGINS` — the analysis WebSocket checks the browser's `Origin`, so without it every scan through the tunnel fails with close code 1006. It prints the public URL; **Ctrl-C** stops all three. Add `-SkipBuild` to reuse the last build, or `-Python C:\path\to\python.exe` to pick an interpreter. The address changes on every run, and anyone with it can read the scan history and submit emails, so stop it when the demo ends.

<details><summary>The same thing by hand, in three terminals</summary>

```powershell
npm --prefix frontend run build; npm --prefix frontend run preview -- --port 5173 --strictPort
```

```powershell
cloudflared tunnel --url http://localhost:5173
```

```powershell
$env:SOC_CORS_ALLOW_ORIGINS = '["http://localhost:5173","http://127.0.0.1:5173","https://<words>.trycloudflare.com"]'; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Put the address the tunnel printed in place of `https://<words>.trycloudflare.com`.
</details>

---

Sentinel-Graph analyses a raw email (`.eml`) the way a Security Operations Centre analyst would, but in seconds: it verifies the sender cryptographically, models the delivery route as a graph and scores it for anomalies, detonates the lure in a sandboxed browser, asks a **local** language model to reason about the evidence, fuses everything into one risk score, and **explains that score feature by feature** with SHAP. Every step streams live to a WebGL dashboard over a WebSocket; every verdict is saved with its indicators (IPs, URLs, sender domains) so an analyst can pivot from one indicator to every scan that saw it, and the delivery route is drawn hop by hop on a 3D globe.

> [!IMPORTANT]
> **Model status (read before quoting results).** Not every engine ships with trained weights. The table below is what the deployed system actually runs, and the API reports the same flags on every analysis (`model_status`) so the dashboard can label stand-in scores.
>
> | Engine | State | Notes |
> |---|---|---|
> | Topology MemAE | ✅ Trained | Research corpus (SpamAssassin ham 2002–03), benign routes only; zero-day threshold calibrated (1.10) |
> | Fusion meta-model | ✅ Trained | Era-matched research corpus, all 12 features: 5-fold stratified OOF ROC-AUC **0.953**, phishing F1 0.834; catches 61.4% of unseen 2023–25 phishing (see [Results](#-results)) |
> | Vision (MobileNetV3 slot) | ⚠️ Placeholder | Untrained stand-in with the real I/O contract until a model is placed in `models/vision/` |
> | Cognitive SLM (Phi-3 slot) | ⚠️ Scripted stand-in | Real onnxruntime-genai path is implemented; activates when Phi-3 ONNX artifacts are installed. The stand-in always answers `CRITICAL`, and that verdict is what history records, so benign mail shows as CRITICAL until a real SLM is installed |
> | Globe hop locations | ⚠️ Partly estimated | Public IPs are looked up; any hop that cannot be located is placed at a hashed stand-in position, drawn dashed and counted on the risk gauge |

---

## 📑 Contents

[Architecture](#-architecture) · [Core innovations](#-core-innovations) · [Security engineering](#-security-engineering) · [Results](#-results) · [Local deployment](#-local-deployment) · [Training](#-training-the-models) · [Testing](#-testing) · [Configuration](#-configuration) · [Repository layout](#-repository-layout) · [Limitations](#-limitations--future-work) · [References](#-references)

---

## 🧱 Architecture

```mermaid
flowchart LR
    EML["📧 Raw .eml"] -->|one binary frame| WS["⚡ FastAPI WebSocket<br/>/ws/api/v1/stream-analysis"]
    WS --> T1["🔐 Tier 1 · Protocol forensics<br/>MIME unpack · Authentication-Results<br/>Received-chain IPs & timestamps<br/>link entropy · coercive wording"]
    T1 --> FAN{{"asyncio.gather<br/>concurrent fan-out"}}
    FAN --> VIS["🌐 Tier 2 · Vision<br/>Playwright detonation (no JS)<br/>→ ONNX screenshot embedding"]
    FAN --> TOPO["🕸️ Tier 3 · Topology<br/>PyG delivery DAG<br/>→ GCN + MemAE reconstruction loss"]
    VIS --> SLM["🧠 Tier 4 · Local ONNX SLM<br/>streamed reasoning + verdict"]
    TOPO --> SLM
    SLM --> FUSE["📊 Late fusion<br/>Random Forest + TreeSHAP"]
    FUSE --> TA["✅ ThreatAssessment<br/>(frozen, strict Pydantic)"]
    TA --> DB[("🗄️ SQLite scan history<br/>scans + IP / URL / domain indicators")]
    DB --> HIST["🔎 REST history API<br/>/api/v1/history/scans · /indicators/{value}"]
    WS -. "telemetry events (every step)" .-> Z["🗂️ Zustand store"]
    Z --> LIVE["🎛️ / Dashboard<br/>upload · verdict and route · globe"]
    Z --> FOR["🔬 /forensics<br/>SHAP · sender identity · NLP and DGA · route graph · pipeline log"]
    Z --> GEO["🌍 Geo-IP resolver<br/>ipapi.co lookup · flagged hashed fallback"]
    GEO --> GLOBE["🌐 WebGL CyberCanvas<br/>graticule globe · hop-to-hop arcs"]
    HIST --> HPAGE["📜 /reports<br/>exports and scan history"]
```

Tier 1 runs first because every later tier needs its output (bodies, URLs, route); vision and topology then run concurrently. The analysis socket lives in the app shell outside React Router's routes, so switching between the dashboard, forensics and reports never tears down a scan in flight; the globe has the dashboard's largest panel, and the verdict beside it lists the hops it plots.

| Stage | Module | What it produces |
|---|---|---|
| MIME unpacking | `src/extractors/mime_parser.py` | Text/HTML bodies and attachments from hostile MIME (malformed boundaries, lying charsets, recursion bombs) |
| URL extraction | `src/extractors/url_extractor.py` | Browser-equivalent URLs (zero-width / bidi / backslash obfuscation removed) |
| Identity | `src/forensics/auth_analyzer.py` | SPF / DKIM / DMARC / ARC verdicts, sender domains, display-name brand spoofing |
| Route | `src/forensics/route_analyzer.py` | Hop count, private-IP leak between public hops, timestamp regression |
| Content heuristics | `src/forensics/dga_detector.py`, `nlp_heuristics.py` | Domain Generation Algorithm (DGA) entropy of each link's registrable label; NLP coercion heuristics (urgency score) |
| Sandbox | `src/vision/sandbox.py` + `egress_proxy.py` | 1024×768 screenshot of the lure, rendered with JavaScript disabled |
| Vision | `src/vision/brand_detector.py` | SHA-256, L2-normalised embedding, `VisionForensics` |
| Topology | `src/topology/graph_builder.py`, `memae_model.py` | Delivery DAG, MemAE anomaly loss, zero-day flag |
| Reasoning | `src/cognitive/prompt_engineer.py`, `slm_inference.py` | Injection-hardened prompt, streamed deduction, extracted verdict |
| Fusion | `src/fusion/meta_scorer.py`, `xai_engine.py` | Phishing probability and exact per-feature SHAP attribution |
| Streaming | `src/core/orchestrator.py`, `app/main.py` | The fan-out pipeline and the WebSocket API |
| Persistence | `src/core/database.py`, `src/models/db_models.py` | Async SQLAlchemy scan records and pivotable indicators |
| History | `src/api/routers/history.py` | Paginated scan log and indicator pivot endpoints |
| Dashboard | `frontend/src/pages/`, `components/CyberCanvas.tsx`, `lib/geoResolver.ts`, `lib/exports.ts` | Dashboard, forensics and reports pages; globe and hop geolocation; JSON/CSV export |

**The 12-feature fusion space** — one row per email, in this order (a saved model takes its columns by name):

| # | Feature | Subsystem | What it measures |
|---|---|---|---|
| 0 | `auth_fail_count` | Protocol forensics | SPF / DKIM / DMARC / ARC results that are `fail` |
| 1 | `display_name_spoof_risk` | Protocol forensics | Brand in the display name (1.0) or only in the subject (0.5) |
| 2 | `private_ip_leak` | Protocol forensics | A private address between public hops |
| 3 | `timestamp_regression` | Protocol forensics | A later hop stamped before an earlier one |
| 4 | `screenshot_hash_exists` | Vision | The lure rendered in the sandbox |
| 5 | `visual_spoof_score` | Vision | Visual similarity to a protected brand |
| 6 | `is_cred_harvester` | Vision | The page collects credentials |
| 7 | `graph_nodes_count` | Topology | Nodes in the delivery DAG |
| 8 | `memae_loss` | Topology (GNN) | MemAE reconstruction loss of the delivery graph |
| 9 | `slm_verdict_severity` | Cognitive SLM | Verdict rank, BENIGN 0 … CRITICAL 3 |
| 10 | `dga_max_entropy` | Content heuristics | **Domain Generation Algorithm (DGA) entropy** of the links |
| 11 | `nlp_urgency_score` | Content heuristics | **NLP coercion heuristics**: coercive-phrase urgency |

Measured on a laptop CPU: Tier 1 completes in **~6 ms** on the demo lure (median of 7 warm runs through the app, 2026-10-31); the content heuristics cost 0.2 ms of that, and ~9 ms on a 95th-percentile (18 KB HTML) phishing email. An earlier end-to-end run with a live detonation (real Chromium, trained models) measured the topology scored at **~90 ms** (concurrently with detonation), detonation **~2.5 s** and the complete assessment **~4 s**.

---

## 💡 Core innovations

### 🕸️ Delivery topology as a graph, scored by a memory-augmented autoencoder

A phishing kit can rewrite every word of its message, but it still has to *deliver* it, and the delivery leaves structure behind: which relays touched it, in what order, through which address spaces, with what clock behaviour. Flat text models (TF-IDF, bag-of-words, even sentence embeddings) discard that relational structure. Sentinel-Graph keeps it:

1. **Graph.** Each email becomes a DAG — sender → relay hops → receiver, plus sender → each URL — with node features `x ∈ ℝ^{N×5}` (one-hot node type ‖ path position or URL character entropy).
2. **Encoder.** Two GCN layers (5 → 32 → 16) propagate `H' = σ(D̂^{-½} Â D̂^{-½} H W)` so each node's latent vector `z_i` reflects its neighbourhood.
3. **Memory addressing.** A learned memory `M ∈ ℝ^{50×16}` stores prototypes of *normal* routing. Each latent addresses it by cosine similarity and a sharpened softmax, `w_i = softmax(cos(z_i, M) / τ)` with `τ = 0.1`.
4. **Hard shrinkage.** `ŵ = ReLU(w − λ)·w / (|w − λ| + ε)` with `λ = 0.05`, then L1 re-normalisation: each node must be rebuilt from a **sparse** mix of a few normal prototypes.
5. **Decoder and score.** `ẑ = ŵ M`, `Â_pred = σ(ẑ ẑᵀ)`; the anomaly score is the off-diagonal binary cross-entropy against the real (undirected) adjacency.

**Why the memory matters (the mathematical advantage).** A plain autoencoder generalises *too well*: it learns to reconstruct anomalies too, so their error stays low. Forcing reconstruction through a small memory of benign prototypes means an unseen topology simply cannot be expressed, and its loss rises (Gong et al., 2019). MemAE trains on **benign mail only**, so it needs no labelled examples of the attack — the property that lets it flag *zero-day* routing tricks a supervised classifier has never seen. The zero-day threshold is the 99th percentile of benign losses measured **out of fold** (1.10).

**What it can see today.** Route nodes carry only their type and position along the path; IP semantics (private range, ASN, reverse-DNS agreement, per-hop clock deltas) are separate fusion features, not node features. The trained MemAE therefore models the *shape* of delivery — route length and link profile — and enriching node features with per-hop attributes is the step that lets it see forged hops directly. The [ablation](#ablation-study-what-each-modality-contributes) confirms it: removing the MemAE loss from the fusion model changes the out-of-fold AUC by 0.00%, because the graph's size already carries that signal.

### 🧠 Local ONNX small language model, not a cloud API

- **Data never leaves the host.** Emails carry personal data; nothing is sent to a third-party model provider, which keeps the system inside data-protection obligations such as India's DPDP Act, 2023.
- **Deterministic.** Greedy decoding: the same evidence yields the same deduction, so verdicts are reproducible for audit.
- **Streamed.** Tokens reach the analyst as they are generated, through the same WebSocket as the telemetry.
- **Injection-hardened.** Attacker text cannot forge template sections, `VERDICT:` lines or chat-role tokens; and the extracted verdict can **escalate but never downgrade** when outputs conflict.
- **One voice, not the judge.** The SLM verdict is one of twelve fusion features; the final score is the meta-model's, explained by SHAP.

### 📊 Explainable late fusion

Twelve features from five subsystems feed a Random Forest. **TreeSHAP** gives exact additive attributions — base value + Σ SHAP = predicted probability (verified in the test suite to 10⁻⁶) — reported per feature and per subsystem (`PROTOCOL_FORENSICS`, `VISION_ENGINE`, `TOPOLOGY_GNN`, `COGNITIVE_SLM`, `CONTENT_HEURISTICS`). The dashboard colours graph edges by the sign of their subsystem's SHAP impact; content heuristics describe the whole message, so they colour none. A saved model names the features it was trained on and receives exactly those columns, by name, so adding a feature never breaks a deployed model: the new feature is ignored (and logged) until a model trained on it is promoted.

### 🔤 Content heuristics: DGA entropy and NLP coercion

Two lexical features computed in Tier 1, by the same helpers in the live pipeline and in training, so the two cannot drift apart:

- **Domain Generation Algorithm (DGA) entropy** (`dga_max_entropy`) — the highest Shannon entropy, H = Σ p log₂(1/p), of any link's *registrable label*, the part left of the public suffix (`login.xkqjfhzyw.co.uk` → `xkqjfhzyw`, 3.17 bits; `google`, 1.92 bits). Subdomains are free attacker padding and are ignored; IP-literal hosts are skipped; the suffix list is offline. Raw entropy is bounded by log₂(length), so long legitimate names score high too. Its class *means* are identical on the research corpus (2.31 vs 2.30 bits), yet the ablation shows it is the stronger content feature: legitimate links cluster at 2.5–3.0 bits (52% of linked mail, against 23% of phishing), while phishing fills both tails — 24% below 2.0 bits (4% of legitimate) and 26% at 3.0 bits or more (17%). A tree splits on both sides; a mean cannot see that.
- **NLP coercion heuristics** (`nlp_urgency_score`) — eight pressure phrases ("immediate action", "account suspended", "verify your identity", …), 0.25 per match, capped at 1, matched in their natural inflections after NFKC folding with invisible characters removed, so zero-width splits and line breaks cannot hide a phrase. The bare phrases fired on 1.5% of phishing; the inflected forms fire on 20.3% of 2004–06 phishing, 7.2% of 2023–25 phishing and 0.1% of legitimate mail.

### ✂️ Receiver-side hop normalisation

`Received` headers are written by both sides of a delivery. The hops the *receiving* provider adds after accepting a message — Gmail's `by`-only hand-offs, a content filter on loopback, internal relays — describe the recipient's mailbox, not the sender. Left in, they let a model learn *which mailbox a training email came from* (a corpus artefact) instead of whether it is phishing. The route analyser walks the chain newest first and strips every hop whose receiving host and verified reverse-DNS name sit in the receiver's own registered domain, keeping the receiver's **entry hop**: its client IP is the last address the sender side presented. HELO names are never trusted, because the sender writes them. Every route feature — hop count, private-IP leak, timestamp regression, the DAG itself, the stored IP indicators — is computed on the sender-side path only.

### 🌍 Resilient, privacy-aware Geo-IP mapping

The globe needs a latitude and longitude for each hop, and a live demo cannot depend on a free API's rate limit. `resolveIPsToCoords` looks up public hop IPs at ipapi.co in parallel (4 s timeout, cached per session) and never rejects: on a network or CORS error, an HTTP 429, ipapi's `200 {"error": true}` or a timeout, the IP is hashed with 32-bit FNV-1a (two independent seeds) into a stable point, `lat = (h₁ mod 18001)/100 − 90`, `lng = (h₂ mod 36000)/100 − 180`. The same IP always lands in the same place, so repeated demos are reproducible.

- **Honest by construction.** Each point is tagged `lookup` or `estimated`; estimated arcs are dashed and the risk gauge reports how many hop locations are stand-ins. An estimate is never presented as where a host is.
- **Privacy-aware.** Private, reserved and malformed addresses are never sent anywhere. `VITE_GEO_LOOKUP=off` keeps every IP on the machine (all points estimated), matching the local-only stance of the SLM.
- **Race-safe.** Coordinates are stored only if no newer scan has started while the lookups were in flight.

---

## 🔒 Security engineering

| Threat | Defence |
|---|---|
| Malformed MIME, recursion bombs, lying charsets | Defect harvesting, depth/part limits, headers-only fallback, charset fallback chain; never raises |
| Forged `Authentication-Results` | Only the trusted authserv-id (or topmost) header counts; comments and quoted strings are blanked; duplicates resolve to the most suspicious result |
| Display-name brand spoofing | NFKC + homoglyph + zero-width + leetspeak folding, token-aligned matching, canonical sender domains that exclude free-mail |
| Sandbox SSRF (`http://169.254.169.254/`) | Every Chromium connection — including redirect hops, which Playwright's routing never sees — goes through a loopback egress proxy that connects only to vetted public IPs (defeats DNS rebinding) |
| Malicious downloads / heavy media | Route interception blocks executables, archives and media; downloads refused; JavaScript disabled; Chromium OS sandbox on |
| Prompt injection | Payload and telemetry folded to one line; template markers and chat tokens neutralised |
| Model-file tampering | Torch checkpoints load with `weights_only=True`; joblib/pickle files must live in a trusted `MODELS_DIR` |
| Cross-site WebSocket hijacking | `Origin` checked against `SOC_CORS_ALLOW_ORIGINS` (CORS does not cover WebSockets) |
| Cross-origin reads of scan history | CORS defaults to the Vite dev origins, never `*`: history exposes subjects, senders and analyst traces |
| Indicator leakage to third parties | Geo lookups skip private/reserved IPs; `VITE_GEO_LOOKUP=off` disables them entirely |

---

## 📈 Results

The deployed models were trained on the **era-matched research corpus** — 4,211 legitimate emails (SpamAssassin easy and hard ham, 2002–03) and 2,361 phishing emails (Jose Nazario, 2004–06), all with intact `Received` chains — using all **twelve** features. They were promoted unchanged from `models_research/` on 2026-10-31; earlier model sets are archived ([below](#previous-models-archived)).

| Out of fold (5-fold stratified) | 12 features (deployed) | 10 features (previous) |
|---|---|---|
| ROC-AUC | **0.953** | 0.926 |
| Phishing precision / recall / F1 at 0.5 | 0.779 / 0.898 / **0.834** | 0.772 / 0.875 / 0.820 |
| Legitimate precision / recall | 0.937 / 0.857 | 0.924 / 0.855 |
| Accuracy | 0.872 | 0.862 |
| MemAE zero-day threshold (99th pct. of OOF benign loss) | 1.10 | 1.10 |

Both columns use the same folds and an identical MemAE (every weight tensor equal), so the difference is the two content heuristics alone. The ROC curve and the per-fold MemAE loss curves are in `models/roc_auc_curve.png` and `models/training_loss.png`.

**Leakage controls** (the reason these numbers can be trusted):

- **Out-of-fold only.** Every reported prediction comes from a model that never saw that email.
- **Cross-fitted MemAE.** Each email's MemAE loss comes from a MemAE trained on the *other* folds' benign mail.
- **No label leak through the SLM.** The SLM verdict was deliberately held constant during training: mapping ham→BENIGN and spam→CRITICAL would have produced a meaningless AUC of 1.0.

**Out-of-time check — quote it alongside the AUC.** On 1,000 Nazario phishing emails from **2023–25**, which no model here was trained on, the deployed models catch **61.4%** at 0.5 (median phishing probability 0.55); the 10-feature models caught 48.8% (0.48) and the 2002 baseline 41.1% (0.40). Recall falls from 89.8% in-distribution to 61.4% twenty years later: the cross-validated AUC describes 2004–06 phishing, not today's. There is no modern legitimate mail, so the out-of-time false-positive rate is unmeasured.

**What the numbers do not show.** Neither source has `Authentication-Results` headers (both predate DMARC), and vision and the SLM could not run per training email, so five of the twelve features (`auth_fail_count`, the three vision features, `slm_verdict_severity`) were constant: the model cannot use them. The [ablation study](#ablation-study-what-each-modality-contributes) below shows which features actually carry the score. Retraining on a modern labelled corpus is still the first item of future work.

**Measured on the demo lure** (`tests/e2e/test_capstone_defense.py -s`): a 2026-style Apple lure with SPF/DMARC failures, a private hop between public relays and a backwards clock scores **61/100** (10-feature models: 55; 2002 baseline: 15). SHAP: `display_name_spoof_risk` +0.310, `private_ip_leak` **−0.243**, `graph_nodes_count` +0.089, `timestamp_regression` +0.064, `memae_loss` +0.044, `nlp_urgency_score` −0.020 (the lure uses no coercive phrase, which counts as weak evidence of legitimate mail). The benign end-to-end email scores **39/100** (10-feature: 29; baseline: 14): still below 50, but the one benign data point we have moved up.

**Why `private_ip_leak` lowers risk — measured, not guessed.** Two-thirds of SpamAssassin's legitimate mail is **mailing-list traffic** (Red Hat's `exmh-workers`, `xent.com`, SourceForge lists), which genuinely travels sender → corporate internal relays (172.16.x, 192.168.x) → public list server. In the research corpus `private_ip_leak` fires on 66.8% of legitimate mail and 3.0% of phishing, so the forest learned "private hop = mailing list = safe". Both corpora carry the confound (SHAP −0.129 in the 2002 baseline, −0.312 with ten features, −0.243 with twelve); a better dataset alone cannot remove it — the monotonic constraints below would forbid it.

**The route model.** On the same probes, the deployed MemAE ranks the forged 3-hop route as more unusual than the benign 1-hop route — loss **0.194** vs **≈ 0** (3.7 × 10⁻¹⁵), neither flagged zero-day — where the 2002 baseline had them backwards (0.0003 vs 0.96, with the benign route falsely flagged). It still sees only route shape, not hop attributes (see *What it can see today*), so the forged hop itself is not what it detects.

**Two training bugs the loss curves exposed.** The first research run had two folds diverge at epoch 4 (training loss 0.18 → 2.14), inflating the zero-day threshold to 4.79. Clipping gradients alone made it worse — a fold climbed to 10.8 and the threshold sat at 27.78 ≈ −ln(10⁻¹²), the ceiling of the old clamped loss. The real fault: `reconstruction_loss` clamped sigmoid probabilities before BCE, which has **zero gradient once saturated**, so a drifting model could never recover. It now computes BCE on logits (identical where unsaturated — the 2002 baseline MemAE scores the demo lure exactly as before — but always differentiable), and all five folds converge (0.25 → 0.11–0.14, validation 0.09–0.16).

### Ablation study: what each modality contributes

`python scripts/run_ablation_study.py` retrains the fusion forest **without** each feature group on the trainer's own five folds (identical for every row) and scores every email out of fold — a drop-column ablation, not zeroing columns at prediction time, which would feed the deployed model inputs it never saw (and that model was trained on this corpus, so scoring it here would be in-sample). The MemAE column holds the trainer's cross-fitted losses. The last column fits each configuration on every research email and applies it to the 1,000 unseen 2023–25 phishing emails.

| Configuration | Features removed | OOF ROC-AUC | F1 @ 0.5 | AUC degradation | 2023–25 phishing caught (n=1000) |
|---|---|---|---|---|---|
| Baseline (all 12 features) | — | 0.953 | 0.834 | — | 61.4% |
| No content heuristics (DGA + NLP) = legacy 10-feature | `dga_max_entropy`, `nlp_urgency_score` | 0.926 | 0.820 | 2.86% | 48.8% |
| No DGA entropy | `dga_max_entropy` | 0.935 | 0.819 | 1.99% | 50.5% |
| No NLP coercion | `nlp_urgency_score` | 0.950 | 0.833 | 0.41% | 57.2% |
| No GNN routing (MemAE loss) | `memae_loss` | 0.953 | 0.839 | 0.00% | 71.6% |
| No topology (MemAE loss + graph size) | `graph_nodes_count`, `memae_loss` | 0.936 | 0.774 | 1.87% | 37.6% |
| No protocol forensics | `auth_fail_count`, `display_name_spoof_risk`, `private_ip_leak`, `timestamp_regression` | 0.934 | 0.791 | 2.08% | 47.2% |

AUC degradation = (baseline AUC − AUC) / baseline AUC. The engine is verified against two independent training runs: the baseline row reproduces the deployed model (0.953 / 0.834 / 61.4%) and the no-content row the archived 10-feature model (0.926 / 0.820 / 48.8%). What it shows:

- **The MemAE loss adds nothing to the fusion score.** Removing it leaves the out-of-fold AUC at 0.953 (0.00%), nudges F1 up (0.839), and *raises* 2023–25 recall from 61.4% to 71.6%. The topology signal the forest uses is the graph's **size**: removing size and loss together costs 1.87% and drops 2023–25 recall to 37.6%. This is what position-only node features predict (see *What it can see today*); per-hop attributes are what would let the GNN add information of its own. The 2023–25 set is phishing only, so the false-positive cost of any configuration on modern mail is unmeasured.
- **DGA entropy is the stronger content feature** (−1.99% AUC and 2023–25 recall 50.5% without it, against −0.41% and 57.2% without coercion), despite equal class means — see *Content heuristics*.
- **Protocol forensics** carry the most in-distribution signal (−2.08%; 2023–25 recall 47.2% without them).
- Vision and SLM features are not ablated: constant in training, removing them changes nothing.

### Previous models (archived)

| Out of fold (5-fold stratified) | 10 features, research corpus | 2002 baseline |
|---|---|---|
| Folder | `models_baseline_10_feature/` | `models_baseline_2002/` |
| Training data | as above | 2,551 ham / 501 spam (SpamAssassin 2002) |
| ROC-AUC | 0.926 | 0.855 |
| Positive class precision / recall at 0.5 | 0.772 / 0.875 (phishing) | 0.634 / 0.477 (spam) |
| Negative class precision / recall | 0.924 / 0.855 | 0.902 / 0.946 |
| Accuracy | 0.862 | 0.869 |
| MemAE zero-day threshold | 1.10 | 0.913 |
| Unseen 2023–25 phishing caught at 0.5 | 48.8% | 41.1% |
| Demo lure | 55/100 | 15/100 |

The 2002 AUC is not directly comparable with the research-corpus AUCs: a different corpus, and it separates *spam* from ham rather than *phishing* from legitimate mail. The fair comparison is on mail none of them saw, the out-of-time row. To roll back, copy the contents of either folder over `models/`.

---

## 🚀 Local deployment

### Requirements

| | Minimum | Tested |
|---|---|---|
| Python | 3.12 (64-bit; 3.15 not yet supported) | 3.14.6 |
| Node.js | 20.19 / 22.12 (Vite 8) | 24.22 LTS |
| CPU / RAM | 4 cores, 8 GB | Windows 11 laptop, CPU only |
| Disk | ~3 GB (PyTorch, Chromium, models) | — |

All engines run on **CPU** out of the box (ONNX Runtime `CPUExecutionProvider`). A GPU only matters once a real SLM is installed: Phi-3-mini-4k-instruct int4 needs ~2.5 GB of model files and ~4 GB of RAM or VRAM; it runs on CPU, and a consumer GPU such as an **NVIDIA RTX 3050 (4–8 GB VRAM)** with the CUDA or DirectML build of `onnxruntime-genai` streams it markedly faster.

### 1 · Backend

```bash
python -m pip install -e ".[dev]"
```

```bash
python -m playwright install chromium
```

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The trained fusion and MemAE models ship in `models/`. On first start, any model that is still missing (the vision model always is) is generated as a clearly-flagged placeholder (`GET /api/v1/health` lists them). Retrain with the next section.

### 2 · Frontend

```bash
cd frontend
```

```bash
npm install
```

```bash
npm run dev -- --port 5173 --strictPort
```

Open **http://localhost:5173** and drop an `.eml` file anywhere in the window (or use the upload panel). Vite proxies `/api` and `/ws` to the backend on port 8000. The sidebar switches between three pages: **Dashboard** (`/`: upload, the verdict with the delivery route, and the globe), **Forensics** (`/forensics`: every feature's value and SHAP impact, sender authentication and identity, the route model, NLP coercion and DGA entropy, the language model's reasoning, the route graph and the pipeline log) and **Reports** (`/reports`: the current assessment as JSON or CSV, and the scan history with a CSV of every saved scan). The old addresses `/live`, `/ml-forensics` and `/history` redirect to them. A scan keeps streaming while you browse. Exported CSV text cells that start with `=`, `+`, `-`, `@` or a tab are prefixed with an apostrophe, so attacker-controlled subjects cannot run as spreadsheet formulas.

To keep every hop IP on the machine during a demo, put `VITE_GEO_LOOKUP=off` in `frontend/.env.local` before `npm run dev` (globe positions are then all estimated and labelled as such).

### 3 · Optional: real SLM

Install `onnxruntime-genai` (CPU, CUDA or DirectML build) and copy a Phi-3-mini ONNX folder — the one containing `genai_config.json` — to `models/phi3/`. On the next start `CognitiveSLM` loads it instead of the stand-in.

---

## 🎓 Training the models

The trainer reads any folder of labelled `.eml` files: `benign/` + `phishing/`, or SpamAssassin's `easy_ham/` + `spam/`. **Candidates go to `models_research/` by default**, never straight to the `models/` the app loads, so a run cannot replace working models before it has been compared. Each run writes `fusion_meta.joblib`, `topology/memae.pt`, a self-verified `memae.onnx`, `training_report.json` (out-of-fold ROC-AUC, phishing precision / recall / F1 at 0.5, per-fold MemAE loss history), `roc_auc_curve.png` and `training_loss.png` (MemAE training vs held-out benign loss per epoch; each fold validates on its own held-out benign mail, so the curve costs no extra data).

**Research corpus (default `--data-dir`, `data/raw/research/`).** Era-matched public mail with intact `Received` chains: SpamAssassin's easy and hard ham (2002–03) against Jose Nazario's early phishing mailboxes (2004–07, CC-BY-4.0), deduplicated by Message-ID and content hash, with attribution written alongside (~85 MB of downloads):

```bash
python scripts/fetch_modern_corpus.py research
```

```bash
python scripts/train_orchestrator.py
```

Enron is deliberately not used: its public release strips `Received` headers, so every benign email would have no route and the route models would learn "has headers" instead of phishing. Real phishing archives trip antivirus; on Windows, Defender quarantines `phishing3.mbox` (2006–07), and the fetch skips a quarantined mailbox and says so rather than failing (the corpus is then 4,211 benign / 2,361 phishing). Do not disable the scanner to get it back; if you want it, exclude only `data\raw\downloads\nazario` and `data\raw\research`.

**Promote a candidate** only after comparing it with the deployed models on mail neither has seen. The shipped models were promoted by backing up `models/` and copying the evaluated candidate files over it, so what ships is byte-for-byte what was measured. Alternatively, `--models-dir models` trains straight into the folder the app loads:

```bash
python scripts/train_orchestrator.py --models-dir models
```

**2002 baseline (archived).** Extract `20021010_easy_ham.tar.bz2` and `20021010_spam.tar.bz2` into `data/raw/spamassassin/`, then pass `--data-dir data/raw/spamassassin`. Retraining will not reproduce the archived weights exactly: MemAE training now clips gradients and computes its loss on logits (see Results).

**Modern corpus (`data/raw/modern_2026/`).** Hand-classified 2023–25 phishing from the same Nazario archive. No public archive of modern legitimate mail keeps full routing headers, so the benign half comes from an mbox you export yourself:

```bash
python scripts/fetch_modern_corpus.py real --limit 1000 --benign-mbox path/to/inbox.mbox
```

`fetch_modern_corpus.py synthetic` writes a separate, clearly-labelled smoke-test corpus to `data/raw/synthetic_2026/`; it exercises the pipeline but never feeds training, because a model trained on generated mail learns the generator. Add `--debug-slice 100` to any training run for a quick check.

---

## 🧪 Testing

```bash
python -m pytest
```

371 tests: unit, property and adversarial cases for every tier, real-Chromium sandbox tests, training-pipeline tests, history API and persistence tests, and `tests/e2e/` — whole-system runs through the WebSocket API with real engine loading. `tests/e2e/test_capstone_defense.py` runs the **deployed** models (skipped until a training run exists) from ingestion to the history API; add `-s` to print the trained model's SHAP breakdown for the demo lure. `python -m pytest -m "not e2e"` skips the slower end-to-end tests; `SOC_LIVE_NETWORK_TESTS=1` adds a live internet detonation. Static checks:

```bash
python -m mypy src tests scripts app
```

```bash
npm --prefix frontend run build
```

---

## 🔧 Configuration

All settings are environment variables with the `SOC_` prefix (or a `.env` file).

| Variable | Default | Purpose |
|---|---|---|
| `SOC_MODELS_DIR` | `./models` | Where every engine loads (or generates) its model |
| `SOC_LOG_DIR` | `./logs` | NDJSON log for SIEM ingestion (`system.log`) |
| `SOC_TRUSTED_AUTHSERV_IDS` | `[]` | Your MX's authserv-id(s); set this in production |
| `SOC_CORS_ALLOW_ORIGINS` | the Vite dev origins (`:5173`) | Browser origins allowed to call the API and stream (`["*"]` allows any) |
| `SOC_DATABASE_URL` | `sqlite+aiosqlite:///<project>/soc_intel.db` | Scan history database |
| `SOC_SANDBOX_TIMEOUT_MS` | `4000` | Navigation budget per detonation |
| `SOC_SANDBOX_CHROMIUM_OS_SANDBOX` | `true` | Disable only where Chromium's sandbox cannot start |
| `SOC_MAX_EMAIL_BYTES` | `16777216` | Largest email the API accepts |
| `VITE_GEO_LOOKUP` (frontend, `frontend/.env.local`) | on | `off` never sends hop IPs to ipapi.co; globe positions are then all estimated |

---

## 📁 Repository layout

```text
app/                 FastAPI app: ConnectionManager + WebSocket endpoint
src/api/routers/     REST history API (scans, indicator pivots)
src/core/            settings, JSON logging, orchestrator, database, shared helpers
src/models/          SQLAlchemy scan and indicator tables
src/extractors/      MIME unpacker, URL extractor
src/forensics/       identity (auth + spoofing), route, DGA-entropy and NLP-coercion analysers
src/vision/          Playwright sandbox, egress proxy, ONNX brand detector
src/topology/        PyG graph builder, GraphMemAE
src/cognitive/       prompt builder, local SLM streaming + verdict extraction
src/fusion/          meta-scorer, SHAP engine
scripts/             train_orchestrator.py (lazy ingestion, cross-fitting, OOF CV),
                     fetch_modern_corpus.py (research: SpamAssassin 2002-03 ham + Nazario 2004-07;
                     real: Nazario 2023-25 + your benign mbox; synthetic smoke tests),
                     run_ablation_study.py (drop-column ablation -> models_research/ablation_results.md),
                     generate_custom_report.py (project report in the SIICS format -> build/report/)
tests/               371 tests, including tests/e2e/
frontend/            React 19 + Vite + Tailwind + Three.js + React Flow dashboard
  src/pages/         Dashboard (/), Forensics (/forensics), Reports (/reports)
docs/                CAPSTONE_PRESENTATION.md (12-min talk), CAPSTONE_DEFENSE.md (5-min talk + Q&A),
                     report/ (UML diagrams as SVG and dashboard snapshots for the project report)
```

---

## 🧭 Limitations & future work

- **Modern training data.** Retrain on a labelled 2020s corpus with `Authentication-Results` headers, and run vision and the SLM during training so their features carry signal.
- **Monotonic fusion.** Constrain spoofing, IP-leak and regression features to only *raise* risk (e.g. `HistGradientBoostingClassifier` with monotonic constraints) so out-of-distribution mail cannot invert them — as `private_ip_leak` currently is on the demo lure.
- **A stronger DGA signal.** Label entropy is the stronger content feature in the ablation, but raw entropy is length-confounded; a character n-gram model of benign domain names is the standard upgrade.
- **Richer graph nodes.** Give each hop node its own attributes (private/bogon flag, ASN change from the previous hop, clock delta, reverse-DNS agreement) so the MemAE can see a forged hop rather than only the route's shape — today its loss adds nothing the graph size does not (ablation), so this is what would let the GNN earn its place in the fusion score.
- **Benign mail for the modern corpus.** The phishing half of `data/raw/modern_2026/` is in place; a consented, exported benign mailbox completes it.
- **Real vision model** and brand centroids for `visual_spoof_score`; credential-form detection for `is_credential_harvester`.
- **Throughput.** Pre-warmed browser pool, URL-result cache, and a job queue in front of the sandbox.
- **Contracts.** Generate the TypeScript types from the Pydantic JSON schema; add CI so the test badge is live.

---

## 📚 References

1. D. Gong et al., "Memorizing Normality to Detect Anomaly: Memory-augmented Deep Autoencoder for Unsupervised Anomaly Detection," *ICCV*, 2019.
2. T. N. Kipf and M. Welling, "Semi-Supervised Classification with Graph Convolutional Networks," *ICLR*, 2017.
3. S. M. Lundberg and S.-I. Lee, "A Unified Approach to Interpreting Model Predictions," *NeurIPS*, 2017.
4. S. M. Lundberg et al., "From local explanations to global understanding with explainable AI for trees," *Nature Machine Intelligence*, 2020.
5. M. Kucherawy, "Message Header Field for Indicating Message Authentication Status," RFC 8601, 2019.

---

<div align="center">

Released under the [MIT License](LICENSE) · © 2026 Uday Babasaheb Baviskar

</div>
