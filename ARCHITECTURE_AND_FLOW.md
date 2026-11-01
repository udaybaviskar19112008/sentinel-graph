# Sentinel-Graph: Architecture and Code Execution Flow

A reading report for the capstone defense. It follows one email from the moment it is dropped on the dashboard to the moment the verdict appears, naming the exact file and function at every step. Numbers are the deployed models' (`models/training_report.json`).

> **How to read this.** Section 1 is the big picture in plain words. Section 2 is the step-by-step trace through the code. Section 3 covers the dashboard's reactivity. Section 4 is a cheat sheet of hard examiner questions with answers grounded in this codebase.

---

## 1 · The high-level architecture

### In one sentence

Sentinel-Graph turns a raw email (`.eml`) into **twelve numbers** describing different kinds of evidence, feeds those numbers to a **Random Forest**, and reports the forest's phishing probability as a 0–100 risk score, with **SHAP** explaining how much each number pushed the score up or down.

### Why it is called "hybrid"

The twelve numbers come from two very different kinds of analysis:

| Kind | What it is | Features it produces |
|---|---|---|
| **Hand-written heuristics** | Deterministic rules a security analyst would apply: do SPF/DKIM/DMARC fail? Does the display name claim a brand the address does not belong to? Does a private IP sit between two public relays? Do timestamps run backwards? How random is the link's domain? How many pressure phrases does the text use? | `auth_fail_count`, `display_name_spoof_risk`, `private_ip_leak`, `timestamp_regression`, `dga_max_entropy`, `nlp_urgency_score` |
| **Learned models** | A **graph neural network** (GCN encoder + memory-augmented autoencoder, "MemAE") that learned what *normal* delivery routes look like; a vision model that embeds a screenshot of the link; a local language model that reads the evidence | `graph_nodes_count`, `memae_loss`, `screenshot_hash_exists`, `visual_spoof_score`, `is_cred_harvester`, `slm_verdict_severity` |

The Random Forest (the "meta-model") then **fuses** both kinds. This pattern is called **late fusion**: each engine works independently and only their outputs are combined.

### The pipeline at a glance

```
.eml file
   │  (one binary WebSocket frame)
   ▼
Tier 1 · Protocol forensics ── MIME unpack, auth headers, Received chain, URLs, DGA, NLP
   │
   ├──────────────── run concurrently (asyncio.gather) ────────────────┐
   ▼                                                                   ▼
Tier 2 · Vision                                              Tier 3 · Topology
Playwright detonation → screenshot → ONNX embedding          route → PyG graph → GCN + MemAE loss
   └───────────────────────────────┬───────────────────────────────────┘
                                   ▼
                     Tier 4 · Local SLM (streams its reasoning)
                                   ▼
                  Late fusion: 12-feature row → Random Forest → TreeSHAP
                                   ▼
             ThreatAssessment → SQLite history → COMPLETE event → dashboard
```

### What is real and what is a stand-in (say this before you are asked)

| Engine | State |
|---|---|
| Fusion Random Forest | ✅ Trained: 5-fold out-of-fold ROC-AUC **0.953**, phishing F1 **0.834** |
| Topology MemAE | ✅ Trained on benign routes only; zero-day threshold **1.10** |
| Vision (MobileNetV3 slot) | ⚠️ Untrained placeholder with the real input/output contract |
| Cognitive SLM (Phi-3 slot) | ⚠️ Scripted stand-in that always answers `CRITICAL` |

The backend reports these flags on every analysis (`AnalysisEngines.model_status` in `src/core/orchestrator.py`), and the dashboard labels stand-in output.

---

## 2 · Code execution flow, step by step

### Step 1 · Ingestion: React → FastAPI WebSocket

**Where the upload starts.** The drop zone is `frontend/src/components/Dropzone.tsx` (not the 3D canvas). Its `onDrop` handler passes the `File` up to `App.tsx`, which owns the socket through the `useThreatSocket` hook. The socket lives in the app shell, outside React Router's `<Routes>`, so changing pages never kills a scan in flight.

**Opening the stream** (`frontend/src/lib/threatStream.ts → openAnalysisStream`):

1. `resetState()` clears the previous scan in the Zustand store.
2. Files over 16 MB are refused in the browser, before any upload.
3. A `WebSocket` opens to `ws://<page host>/ws/api/v1/stream-analysis`. Vite proxies it to the backend on port 8000.
4. On `onopen`, the file is read as an `ArrayBuffer` and sent as **one binary frame**.
5. `isCurrent(socket)` guards every handler: when a second email is dropped mid-scan, the old socket's late events are ignored instead of overwriting the new scan.

**Receiving it** (`app/main.py → stream_analysis`):

```python
if not _origin_allowed(websocket.headers.get("origin"), current.CORS_ALLOW_ORIGINS):
    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)   # cross-site hijack defence
    return
await manager.connect(websocket)
raw_bytes = await _receive_email(websocket, current.MAX_EMAIL_BYTES)  # binary frame, size-checked
await stream_analysis_pipeline(raw_bytes, websocket, manager, engines=..., db_session=...)
```

- **Origin check.** CORS does not apply to WebSockets, so the server checks the `Origin` header itself. Without that check, any website could open a socket to your local backend.
- **`ConnectionManager`** keeps one `asyncio.Lock` per socket. The vision and topology branches report concurrently, and the lock stops their JSON messages interleaving on the wire.
- **Models are loaded once** at startup (`lifespan` → `AnalysisEngines.load`, in a threadpool) and shared by every analysis.

Every event the server sends carries `analysis_id` (also the log correlation id) and `elapsed_ms`.

### Step 2 · Payload unpacking: MIME and BeautifulSoup

`src/core/orchestrator.py → _protocol_forensics` runs all of Tier 1 in the threadpool, because parsing is blocking CPU work:

```python
message, text, html, _ = unpack_email(raw_bytes)          # MIME
identity = analyze_identity(message, brands)              # SPF/DKIM/DMARC/ARC, brand spoof
routing  = analyze_routing(message)                       # Received chain
urls     = extract_urls(html, text)                       # links
visible_html = visible_text(html)                         # BeautifulSoup, parsed once
```

**MIME (`src/extractors/mime_parser.py → unpack_email`).** Uses Python's `email` parser with `policy.default`. Phishing kits deliberately send broken MIME (malformed boundaries, lying charsets, absurd nesting) to crash scanners, so this module **never raises**. It retries headers-only when a parse fails, harvests the stdlib's registered *defects* and logs them, and decodes each part's charset defensively (`src/core/charsets.py`).

**URLs (`src/extractors/url_extractor.py → extract_urls`).** BeautifulSoup (`html.parser`) walks `href`/`src`-style attributes in the HTML; a regex scans the plain text. Every candidate is normalised the way a browser would see it: zero-width and bidi characters removed, backslashes fixed, relative links resolved against `<base>`, trailing prose punctuation trimmed. This defeats the trick of hiding a URL from a scanner while the browser still follows it.

**Visible text (`src/forensics/nlp_heuristics.py → visible_text`).** BeautifulSoup's `get_text(" ")` gives the text a reader actually sees. It is computed once and shared by the language-model prompt and the coercion score.

**Identity (`src/forensics/auth_analyzer.py → analyze_identity`).** Reads `Authentication-Results` (only from trusted authserv-ids, so an attacker cannot forge a "pass" header of their own), extracts SPF/DKIM/DMARC/ARC verdicts, and checks whether the `From` display name names a high-risk brand (e.g. "Apple Support") that the sending domain does not belong to. Brand matching works on a confusable-folded "skeleton", so `Pаypal` with a Cyrillic `а` still matches.

### Step 3 · Feature engineering: DGA entropy and NLP

Both features are computed in `_protocol_forensics` and stored on `HeaderForensics`.

#### DGA entropy (`src/forensics/dga_detector.py → analyze_dga_risk`)

Malware and phishing kits often mint throwaway domains with a **domain generation algorithm** (DGA), e.g. `xkqjfhzyw.com`. Random strings use many different characters about equally often, so their **Shannon entropy** is high.

1. For each URL, take the hostname (`urlsplit`) and strip invisible characters.
2. **`tldextract` finds the registrable label** (`src/core/domains.py → registrable_label`): `login.secure-paypa1.co.uk` → `secure-paypa1`. Only that label is scored, because subdomains are free attacker padding and the public suffix (`.co.uk`) is shared by everyone. `tldextract` runs **offline** (`suffix_list_urls=()`, the bundled suffix list) so scoring never touches the network. Reserved TLDs such as `.invalid` fall back to the second-to-last label. IP-literal hosts are skipped: an address is not a generated name.
3. Compute entropy:

```python
def calculate_shannon_entropy(string: str) -> float:
    # H(X) = Σ p(x) · log2(1/p(x)) over the characters, in bits
    length = len(string)
    return sum(count / length * math.log2(length / count) for count in Counter(string).values())
```

4. The feature is the **maximum** entropy over all links: one generated domain is enough.

Example: `google` → about 1.92 bits (it reuses `o` and `g`); `xkqjfhzyw` → 3.17 bits (nine distinct letters). The dashboard shows a 2.5–3.0-bit "legitimate band". It is a **two-sided** scale, not "higher is worse": entropy is bounded by log2(length), so long, legitimate names score high too. The forest learns where the risk sits.

#### NLP coercion score (`src/forensics/nlp_heuristics.py → CoercionAnalyzer`)

One compiled regular expression with **eight phrase alternatives** that pressure a reader to act before thinking:

```
immediate action · account … suspended · verify your identity · invoice is attached
password … expires · unauthorized access · final notice · click here to cancel
```

How it fires:

1. **Fold the text first** (`_fold`): NFKC normalisation, case-folding, removal of invisible format characters, whitespace collapsed. A zero-width space or a line break can no longer split "final notice".
2. **Inflections are matched**: `account (\w+\W+){0,3}? suspen(d|ded|ds|ding|sion)` catches "account has been suspended". The bare phrases fired on only 1.5% of research phishing; the inflected forms fire on 20.3% of phishing and 0.1% of legitimate mail.
3. **Bounded gaps** (`{0,3}`) keep matching linear in text length, so there's no catastrophic backtracking (ReDoS). Only the first 64 KB is scanned.
4. **Score** = 0.25 × number of matches, capped at 1.0 (four phrases).
5. `score_parts` takes the **higher** of the plain-text and HTML scores, not the sum: `multipart/alternative` carries the same message twice, and a harmless plain-text decoy must not hide a coercive HTML part.

Tier 1 then emits `{"phase": "TIER_1", "findings": …, "url_count": …}`. It takes about 6 ms on the demo lure.

### Step 3½ · The vision branch (runs concurrently with Step 4)

`_vision_branch` in the orchestrator detonates **the first URL** (in almost every campaign the first link is the lure) with `src/vision/sandbox.py → detonate_and_capture`:

- headless Chromium **with its OS sandbox on** (`--no-sandbox` is deliberately absent);
- a **fresh browser per URL**, **JavaScript disabled**, downloads refused;
- route interception aborts executables, archives, heavy media, fonts and websockets;
- **every** connection, redirects included, goes through `src/vision/egress_proxy.py`, which resolves the host itself and refuses any non-public address, so a lure cannot pivot into `192.168.x.x` or cloud metadata endpoints (SSRF defence);
- a 4-second navigation budget (`SOC_SANDBOX_TIMEOUT_MS`).

The screenshot goes to `VisualSpoofDetector.analyze_screenshot` (ONNX Runtime). That model is currently a placeholder, so its three features are recorded but carry no learned meaning.

### Step 4 · Topology mapping: headers → graph → MemAE

#### 4a · Reading the route (`src/forensics/route_analyzer.py → analyze_routing`)

Each `Received:` header is one hop. They are stacked newest-first, so the code reverses them. It then:

- **strips the receiver's own internal hops** (`_sender_side`) using only facts the receiver recorded, never the sender-chosen HELO name, so an attacker cannot fake being "internal";
- flags **`private_ip_leak`**: a private/bogon IP strictly *between* two public hops (`_leaked_hops`). Private hops at the very start (LAN submission) or end (your own delivery) are normal;
- flags **`timestamp_regression`**: a later hop stamped earlier than the previous one, beyond clock-skew tolerance (a sign of forged headers);
- returns `route_hop_count` and the hop IPs (used for the globe and the indicator history).

#### 4b · Building the graph (`src/topology/graph_builder.py → build_email_dag`)

The route becomes a PyTorch Geometric `Data` object:

```
Sender(0) → Hop 1 → Hop 2 → … → Hop N → Receiver
    └──→ URL 1, URL 2, …            (the sender links to every URL)
```

- **Node features `x` = `[N, 5]`**: a one-hot node type (SENDER, RELAY_HOP, RECEIVER, URL) plus one score in [0, 1], which is the position along the path for route nodes and the normalised character entropy for URL nodes.
- Every edge goes from a lower to a higher index, so the graph is **acyclic by construction** (a DAG).
- Hops and URLs are capped at 64 each, so a hostile email cannot build a giant graph.

The orchestrator emits `TOPOLOGY "Delivery graph built"` with a JSON layout **before** scoring, so the dashboard can draw the route immediately.

#### 4c · Scoring it (`src/topology/memae_model.py → GraphMemAE`)

The MemAE is an **autoencoder**: it compresses the graph and tries to rebuild it. It was trained **only on benign routes**, so it rebuilds normal routes well and strange routes badly. The **reconstruction error is the anomaly score**.

```
encode   x, edges ─► GCNConv(5→32) ─► ReLU ─► GCNConv(32→16) ─► latent z  (one 16-d vector per node)
address  z ─► cosine similarity to 50 memory slots ─► softmax(/0.1) ─► hard_shrink(0.05) ─► weights w
rebuild  ẑ = w · Memory                          (each node is re-expressed from "normal" prototypes)
decode   Â = sigmoid(ẑ ẑᵀ)                       (predict which node pairs are connected)
loss     BCE(Â, A) over off-diagonal pairs        ← the anomaly score (memae_loss)
```

Key ideas to explain:

- **Message passing runs undirected** (`to_undirected` in `encode`). On the directed DAG, the sender node would never receive information from anything but itself.
- **The memory is the trick.** A plain autoencoder can become so good that it rebuilds anomalies too. The MemAE forces every latent vector to be rebuilt *from a small memory of 50 learned "normal routing" prototypes*. A route unlike anything in memory can't be expressed, so it reconstructs badly.
- **Sparse addressing** (`hard_shrink`): after the softmax, weights below 0.05 are zeroed and each row is re-normalised. Each node can therefore only draw on a *few* prototypes, which stops it blending many slots into an exact copy of an anomaly. The relaxation `relu(w − t) · w / |w − t|` keeps a gradient path for training. A row with nothing above the threshold keeps its single strongest slot.
- **Temperature 0.1** sharpens the softmax: over 50 slots an unsharpened softmax averages 0.02 per slot, and the 0.05 threshold would erase almost everything.
- **Zero-day flag**: `loss > 1.10`, the 99th percentile of out-of-fold benign losses.

The two features handed to fusion are `graph_nodes_count` and `memae_loss`.

### Step 4½ · The cognitive SLM

`build_soc_prompt` (`src/cognitive/prompt_engineer.py`) packs the email text (first 500 characters) and every finding into a prompt. Every attacker-influenced string is folded onto one plain line, and anything that could forge the template's section markers, the verdict line or the model's chat-role tokens is neutralised (prompt-injection defence). Text that merely *argues* with the model can't be stopped that way, so `extract_verdict` never lets the model's verdict downgrade on its own. `CognitiveSLM.stream_reasoning` streams tokens; each one is sent as `{"phase": "SLM_REASONING", "token": …}`. `extract_verdict` pulls the final verdict (BENIGN / SUSPICIOUS / CRITICAL…), falling back to SUSPICIOUS if none is found. Today this is the scripted stand-in.

### Step 5 · Meta-scoring: twelve features → one risk score

`FusionMetaModel._build_feature_vector` (`src/fusion/meta_scorer.py`) assembles one row in the fixed `FEATURES` order:

| # | Feature | Source |
|---|---|---|
| 1 | `auth_fail_count` | number of SPF/DKIM/DMARC/ARC = fail |
| 2 | `display_name_spoof_risk` | brand in display name, foreign domain |
| 3 | `private_ip_leak` | private hop between public hops |
| 4 | `timestamp_regression` | clock runs backwards |
| 5 | `screenshot_hash_exists` | detonation produced a screenshot |
| 6 | `visual_spoof_score` | vision model |
| 7 | `is_cred_harvester` | vision model |
| 8 | `graph_nodes_count` | delivery graph size |
| 9 | `memae_loss` | MemAE reconstruction loss |
| 10 | `slm_verdict_severity` | SLM verdict as a rank |
| 11 | `dga_max_entropy` | highest link-label entropy |
| 12 | `nlp_urgency_score` | coercion score |

Then:

1. **Sanitise** (`as_feature_row`): NaN → 0, −∞ → 0, but **+∞ → 1**, so an unboundedly anomalous MemAE loss never reads as perfectly normal.
2. **Select columns by name.** The saved bundle records the feature names it was trained on, and `predict_risk` hands the model exactly those columns. An older 10-feature model keeps working unchanged; a model naming an unknown feature is refused at load.
3. **Predict**: `RandomForestClassifier(n_estimators=100, max_depth=6)` → `predict_proba` for class 1 (phishing).
4. **Explain** (`src/fusion/xai_engine.py`): `shap.TreeExplainer` computes exact, additive SHAP values: *base value + Σ contributions = predicted probability*. That's why the ML-forensics page can show "display-name spoof +0.31".
5. `overall_risk = round(probability × 100)`.

The result is a frozen, strictly validated Pydantic `ThreatAssessment` (`src/schemas.py`). It is saved to SQLite with its indicators (IPs, URLs, sender domains) by `_save_scan`. A database failure is logged and rolled back, never raised, so the analyst still gets the verdict. Finally one `COMPLETE` event carries the assessment, verdict, probability, SHAP contributions, model status, graph layout and `scan_id`.

### Back to React: the Zustand store

`applyServerMessage` (`frontend/src/lib/threatStream.ts`) folds each event into `useThreatStore` (`frontend/src/store/useThreatStore.ts`):

| Event | Store update |
|---|---|
| `TIER_1` | `setHeaderFindings` (the heuristic meters fill) |
| `TOPOLOGY` with `graph_layout` | `setGraph` (the React Flow route map draws) |
| `SLM_REASONING` | `appendSlmToken` (the reasoning streams in live) |
| `COMPLETE` | `setAssessment` (gauge, SHAP, verdict), then `plotRoute` geolocates the hop IPs for the globe |
| `{"error": …}` | phase `ERROR`, logged |
| every event | `setPhase`, `addLog` (pipeline log) |

`plotRoute` checks `analysisId` before writing, so a slow geolocation from an old scan cannot paint over a new one.

---

## 3 · UI/UX reactivity

> **Note on versions.** This section describes the dashboard as committed on `master`. The working tree currently holds an uncommitted restyle (a flatter "data-terminal" look) that replaces the glass panels. `CameraRig` is the same in both.

### Glassmorphism

The committed theme puts frosted-glass panels over the animated 3D globe:

```css
/* frontend/src/index.css */
.glass-panel {
  @apply rounded-3xl border border-glass-border bg-glass-base shadow-2xl backdrop-blur-2xl;
}
```

- `bg-glass-base` is a translucent fill and `border-glass-border` a faint light edge (tokens in `tailwind.config.js` / `src/theme/colors.ts`).
- `backdrop-blur-2xl` blurs **whatever is behind the panel**, here the WebGL globe, which gives the frosted look.
- Hard-won rules in this codebase:
  - **Blur goes on individual panels**, never on a full-screen layer, or the globe disappears.
  - **No ancestor may keep a CSS `filter`.** Any `filter` on a parent silently disables `backdrop-filter` on its children, so route transitions must end at `filter: none`.
  - React Flow's control overrides sit **outside** `@layer`: Tailwind purges layered rules whose class names only appear at runtime.
  - The canvas wrapper stays at `z-0`; `-z-10` would paint it under the page background.

### How `CameraRig` reacts to Zustand (`frontend/src/components/CyberCanvas.tsx`)

The 3D scene is React Three Fiber. `CameraRig` wraps the globe in a `<group>` and drives it **every frame**:

```tsx
useFrame((state, delta) => {
  const { currentPhase, socketStatus, geoCoordinates } = useThreatStore.getState()  // read, don't subscribe
  const stance = stanceOf(currentPhase, socketStatus)            // idle | analysing | complete
  const framing = stance === 'complete' && geoCoordinates.length > 0

  spin.current = THREE.MathUtils.damp(spin.current, SPIN[stance], SMOOTHING, delta)
  if (framing) group.rotation.y = dampAngle(group.rotation.y, facingYaw(geoCoordinates), delta)
  else         group.rotation.y += spin.current * delta

  const z = framing ? CAMERA_Z_FRAMED : CAMERA_Z_IDLE           // 7 vs 12
  state.camera.position.z = THREE.MathUtils.damp(state.camera.position.z, z, SMOOTHING, delta)
})
```

1. **It polls the store with `getState()` inside the frame loop instead of subscribing.** A subscription would re-render the React component on every telemetry event; polling 60 times a second costs nothing and never touches React. The animation stays smooth while hundreds of SLM tokens arrive.
2. **The stance is derived.** The store has no "analysing" phase: `stanceOf` treats "IDLE but the socket is connecting/connected" as the moment an upload starts, `COMPLETE` as complete, and `ERROR` as idle.
3. **Spin**: 0.06 rad/s idle → **0.6 rad/s** (ten times faster) while analysing → back to 0.06.
4. **Zoom and face**: when the verdict *and* the hop locations have arrived, the camera pushes in from z = 12 to z = 7, and the globe turns so the centre of the route faces the camera (`facingYaw`; `dampAngle` turns the shortest way round).
5. **Frame-rate independent**: `damp` is an exponential approach, `1 − e^(−2.5·Δt)`, so the motion feels the same at 30 or 144 fps.
6. **Accessibility**: with `prefers-reduced-motion`, the spin is cut to 20% and the camera jumps instead of gliding.

The canvas lives in `Layout`, outside the routes, so switching pages never destroys the WebGL context.

---

## 4 · Technical Q&A: defense cheat sheet

### Q1. Why WebSockets instead of a REST endpoint?

**A.** The analysis is a **stream of partial results**, not one answer. Tier 1 finishes in milliseconds, the delivery graph is drawn before it is scored, vision and topology report independently as they finish, and the SLM produces tokens one at a time. A WebSocket lets the server **push** each event the moment it exists, over one connection, with per-event timing (`elapsed_ms`). With REST I would need polling or one long blocking request that shows nothing until the end. Two details show I handled the extra risk: a per-socket `asyncio.Lock` serialises concurrent sends, and because CORS does **not** protect WebSockets, the server checks the `Origin` header itself and closes disallowed connections with code 1008. History, which is plain request/response, *is* REST (`/api/v1/history/...`).

### Q2. How did you deal with the gradient problem in training the MemAE?

**A.** Be precise here: it was not the classic deep-network *vanishing gradient*, it was **gradient death from saturation**. The first loss computed binary cross-entropy on probabilities clamped to `[1e-12, 1]`. Once the sigmoid saturated, the clamp's gradient was exactly zero, so a model that drifted there could never recover: on the research corpus, training loss climbed to the clamp's ceiling, −ln(1e−12) ≈ 27.6. The fix in `reconstruction_loss` is `binary_cross_entropy_with_logits` on the raw logits, which uses the log-sum-exp form and always keeps a gradient. It gives identical values wherever the sigmoid is not saturated. A second design choice protects gradients in the memory addressing: `hard_shrink` uses the relaxation `relu(w − t)·w/|w − t|` instead of a hard `if w < t: 0`, so sparse addressing stays differentiable. The training logs (`models/training_report.json`) show train and held-out loss falling together, about 0.24 → 0.11 over five epochs.

### Q3. Your ablation shows removing the MemAE does not change AUC. Why keep it?

**A.** I report that result openly. Dropping `memae_loss` changes out-of-fold AUC by 0.00%, and even raises recall on 2023–25 phishing from 61.4% to 71.6%. I kept it for three reasons:
1. **The AUC is a tie**, not a loss, in distribution.
2. **The 71.6% is measured on a phishing-only set.** There is no modern legitimate mail, so the false-positive cost of that change is **unmeasured**. Promoting a model on half the evidence would be the real mistake.
3. **I know why it is redundant today.** The graph's only per-node information is node type and path position, so the MemAE mostly re-learns graph *size*, which `graph_nodes_count` already gives the forest. The architecture is ready for per-hop attributes (ASN, geo distance, TLS version); once those exist, the MemAE has signal the counts cannot carry. Until then it still gives an explainable **zero-day route flag** (loss > 1.10) that analysts can read on its own.

### Q4. Why a Random Forest for fusion, not a neural network?

**A.** Three reasons tied to this data:
- **Size and shape**: 6,572 labelled emails and 12 tabular features of mixed types (counts, flags, entropies, losses). Tree ensembles are the strongest default for small tabular data, need no feature scaling, and handle the binary flags naturally.
- **Exact explanations**: `shap.TreeExplainer` computes **exact** Shapley values for trees in polynomial time, and they are additive (base value + contributions = probability). For a SOC tool, "why" matters as much as "what".
- **Robustness**: `max_depth=6`, 100 trees and bagging limit overfitting. The model is versioned with its feature names, so it can be swapped safely.

### Q5. How do you know 0.953 is not inflated by leakage?

**A.** Three controls:
1. **Out-of-fold only**: 5-fold stratified cross-validation; every prediction comes from a model that never saw that email.
2. **Cross-fitted MemAE**: each email's `memae_loss` comes from a MemAE trained on the *other* folds' benign mail. Otherwise the topology feature would have memorised the test routes.
3. **No SLM label leak**: the SLM verdict was held constant during training. Mapping ham → BENIGN and spam → CRITICAL would have produced a meaningless AUC of 1.0.

I also quote the **honest limit** next to the AUC: on 1,000 unseen phishing emails from 2023–25, recall drops to 61.4%, because the training data is from 2002–06. I also know of one learned confound: `private_ip_leak` fires on 66.8% of the legitimate mailing-list mail but only 3% of phishing, so the forest learned it *inverted* (SHAP −0.24 on the demo lure). Retraining on modern labelled mail is future work item one.

### Bonus quick answers

| Question | One-line answer |
|---|---|
| Why does the badge say CRITICAL on a benign email? | The SLM is a scripted stand-in until Phi-3 ONNX files are installed; read the risk number and evidence panels. |
| Is it safe to open phishing links? | Chromium OS sandbox, a fresh browser per URL, no JavaScript, no downloads, and an egress proxy that only reaches public IPs. |
| Can an attacker fake a "pass" in the headers? | Only `Authentication-Results` from trusted authserv-ids are read (`SOC_TRUSTED_AUTHSERV_IDS`). |
| Does anything leave the machine? | The models run locally on CPU. Only the sandbox visits the link, and the globe can geolocate hop IPs (turn that off with `VITE_GEO_LOOKUP=off`). |
| Why `asyncio.gather` for vision + topology? | They are independent; running them together hides the slow browser detonation behind the graph work. |

---

## Appendix · Where to find things

| Concern | File |
|---|---|
| WebSocket endpoint, origin check | `app/main.py` |
| Pipeline orchestration | `src/core/orchestrator.py` |
| MIME / URLs | `src/extractors/mime_parser.py`, `src/extractors/url_extractor.py` |
| Identity, route, DGA, NLP | `src/forensics/auth_analyzer.py`, `route_analyzer.py`, `dga_detector.py`, `nlp_heuristics.py` |
| Graph + MemAE | `src/topology/graph_builder.py`, `src/topology/memae_model.py` |
| Sandbox | `src/vision/sandbox.py`, `src/vision/egress_proxy.py` |
| Fusion + SHAP | `src/fusion/meta_scorer.py`, `src/fusion/xai_engine.py` |
| Training / ablation | `scripts/train_orchestrator.py`, `scripts/run_ablation_study.py` |
| Socket client, store | `frontend/src/lib/threatStream.ts`, `frontend/src/store/useThreatStore.ts` |
| Globe + CameraRig | `frontend/src/components/CyberCanvas.tsx` |
| End-to-end defense test | `tests/e2e/test_capstone_defense.py` |
