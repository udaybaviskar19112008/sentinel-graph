# Sentinel-Graph — Capstone Defense Script

**Presenter:** Uday Babasaheb Baviskar · B.E. Information Technology · JSPM Jayawantrao Sawant College of Engineering
**Format:** 8 slides · ~12 minutes (≈90 s per slide) · live demo optional after Slide 6
**Rule for the whole talk:** every number below was measured on this codebase. Quote them exactly; do not round up.

> **Naming note (Slide 2).** The brief proposed "Cyber-Kinetic Graphs". In security literature *cyber-kinetic* means attacks with physical-world effects (power grids, industrial control), so an examiner could challenge it. This script uses **delivery-topology graphs**, which says exactly what the graph models.

---

## 📇 Facts card (memorise)

| | |
|---|---|
| OOF ROC-AUC (5-fold stratified, SpamAssassin 2002, 3,052 emails) | **0.855** |
| Spam precision / recall @ 0.5 · Ham precision / recall | 0.634 / 0.477 · 0.902 / 0.946 |
| MemAE | GCN 5→32→16 · memory 50×16 · τ = 0.1 · λ = 0.05 · zero-day threshold 0.913 (99th pct. OOF benign) |
| Latency (laptop CPU) | Tier 1 ≈ 60 ms · topology ≈ 90 ms · detonation ≈ 2.5 s · full assessment ≈ 4 s |
| Tests | 306 automated tests, including whole-system WebSocket runs |
| Trained engines | MemAE, fusion meta-model |
| Stand-ins (flagged in every API response) | Vision model, SLM |

---

## Slide 1 — Title & Problem Statement

**On the slide**
- **Sentinel-Graph:** Multimodal AI-Assisted Phishing & Threat Intelligence Detection
- Phishing is still the most common initial access vector
- Modern kits defeat text classifiers: LLM-written lures, homoglyphs, zero-width characters, image-only bodies
- Text is cheap to change — **delivery infrastructure and behaviour are not**
- Goal: an analyst-grade verdict in seconds, with every decision explained

> **Speaker Notes:** Good morning. My project is Sentinel-Graph, a multimodal system for detecting phishing and explaining why. The problem is simple to state. Most phishing filters read the words of an email. Modern phishing operations know that, so they change the words: a language model writes a fluent, unique lure for every target; brand names are spelled with Cyrillic look-alike letters or split by invisible zero-width characters; some messages have no readable text at all, just an image. A model that only reads text is reading the part the attacker controls best. What the attacker cannot rewrite so easily is how the email was delivered and what its link actually does when you open it. Sentinel-Graph is built around that observation: it looks at the protocol evidence, the delivery route, the rendered landing page and a reasoning model, and it explains every verdict feature by feature.

---

## Slide 2 — The Core Innovation: from TF-IDF Classification to Delivery-Topology Graphs

**On the slide**
- Classic approach: email → TF-IDF / embeddings → classifier → *spam / not spam*
- Sentinel-Graph: email → **four evidence tiers** → late fusion → **risk + explanation**
- Delivery route modelled as a **graph**, scored by an unsupervised **memory-augmented autoencoder**
- Every verdict decomposed with **exact SHAP** attributions
- All inference **local**: no email leaves the host

> **Speaker Notes:** The classic pipeline turns an email into a bag of word weights and asks a classifier for a label. It gives you a label and nothing else, and it learns only what attackers have already done. My approach changes two things. First, I treat the delivery path as a graph — sender, every relay hop, the receiver, and every link — and I score that graph with a memory-augmented autoencoder trained only on legitimate mail. It learns what normal delivery looks like, so it can flag a route it has never seen, without needing a labelled example of that attack. Second, I never output a bare label. Four tiers of evidence are fused by a meta-model, and SHAP tells the analyst exactly how much each piece of evidence moved the score. And everything runs on the analyst's own machine.

---

## Slide 3 — Tiers 1 & 2: Protocol Forensics and DOM Detonation

**On the slide**
- **Tier 1 — Protocol forensics (~60 ms)**
  - Hardened MIME parsing: malformed boundaries, lying charsets, recursion bombs
  - SPF / DKIM / DMARC / ARC from the *trusted* `Authentication-Results` header only
  - Route checks: private IP between public hops · timestamps running backwards
  - Display-name spoofing: homoglyph, zero-width and leetspeak folding
- **Tier 2 — Sandbox detonation (~2.5 s)**
  - Headless Chromium per URL: JavaScript off, downloads refused, executables/media blocked
  - **Egress proxy:** every connection — including redirects — may only reach public IPs

> **Speaker Notes:** Tier one is deterministic forensics. The parser survives deliberately broken MIME — I test it with a five-thousand-level nested message that crashes Python's own parser, and it falls back cleanly. Authentication results are read only from the header our own mail server wrote, because anything lower in the stack could be forged by the sender, and I blank out comments and quoted strings first, because mail servers copy attacker-controlled text into them. The route analyser flags a private address sitting between two public hops, and timestamps that run backwards — both signs of injected headers. Tier two opens the link in a disposable headless browser. While building it, I found that Playwright's request routing never sees redirect hops: a harmless-looking page could redirect the sandbox to the cloud metadata address and leak credentials. So every browser connection goes through a small egress proxy that resolves the host itself and connects only to vetted public addresses. A test proves that each redirect hop passes through it.

---

## Slide 4 — Tier 3: The PyTorch MemAE Routing Graph

**On the slide**
- Email → DAG: **sender → hops → receiver**, **sender → URLs**; node features `x ∈ ℝ^{N×5}`
- **Encode:** 2 × GCN, `H' = σ(D̂^{-½} Â D̂^{-½} H W)`, 5 → 32 → 16
- **Address memory** `M ∈ ℝ^{50×16}`: `w = softmax(cos(z, M) / τ)`, τ = 0.1
- **Hard shrinkage:** `ŵ = ReLU(w − λ)·w / (|w − λ| + ε)`, λ = 0.05, then re-normalise
- **Decode:** `ẑ = ŵM`, `Â = σ(ẑẑᵀ)` · **score** = BCE vs real adjacency
- Trained on **benign mail only** · zero-day if loss > **0.913** (99th pct. of out-of-fold benign losses)

> **Speaker Notes:** Each email becomes a small directed graph. Two graph-convolution layers turn every node into a sixteen-dimensional vector that reflects its neighbourhood. The key component is the memory: fifty learned prototype vectors of normal routing. Each node vector is compared with every slot by cosine similarity, and a sharpened softmax — temperature zero point one — turns that into addressing weights. Then hard shrinkage zeroes every weight below zero point zero five and re-normalises the rest. That forces each node to be rebuilt from only a few normal prototypes. The decoder predicts the adjacency matrix from those rebuilt vectors, and the reconstruction error is the anomaly score. Why the memory? An ordinary autoencoder generalises too well: it learns to reconstruct anomalies too. With the memory, an unfamiliar topology simply cannot be expressed, so its error rises. Two details matter for rigour. With fifty slots, an unsharpened softmax gives each slot about two percent, below the threshold, so without the temperature nothing would survive; I measured two to seven active slots per node. And the zero-day threshold is not a guess — it is the ninety-ninth percentile of benign losses measured out of fold.

---

## Slide 5 — Tier 4: The Local ONNX SLM

**On the slide**
- Small language model via **ONNX Runtime GenAI** (Phi-3-mini slot) — runs on the host
- **Privacy:** no email content sent to a third party (DPDP Act, 2023)
- **Deterministic:** greedy decoding → reproducible, auditable reasoning
- **Streamed** token by token to the analyst's screen
- **Injection-hardened:** payload cannot forge sections, verdict lines or chat-role tokens
- Verdict **escalates, never downgrades** · it is *one of ten* fusion features, not the judge

> **Speaker Notes:** Tier four is a language model that writes a short forensic deduction and a verdict. It runs locally through ONNX Runtime's generative API. That choice is about trust. An email is personal data; sending it to a cloud model is a data transfer we would have to justify under India's data protection law, and we would lose control over retention. Locally, the same evidence always produces the same reasoning, because decoding is greedy, so an auditor can reproduce a verdict. The prompt is engineered against injection: the email body is folded onto one line, and anything resembling our section markers, a verdict line, or the model's own chat tokens is neutralised. When the model's output contains conflicting verdicts, extraction takes the most severe, so text echoed from the email can raise a verdict but never lower it. To be precise about the current state: the inference path is implemented and tested against the library's API, and the deployment runs a clearly-flagged scripted stand-in until the Phi-3 model files are installed.

---

## Slide 6 — The SOC Dashboard

**On the slide**
- **FastAPI WebSocket:** one email per connection, a telemetry event at every step
- Vision and topology run **concurrently** — topology finishes (~90 ms) while the sandbox is still rendering
- **React 19 + Zustand** store · **React Flow** delivery map · **Three.js** globe with hop-to-hop arcs · **History** page
- Edges coloured by the **sign of their SHAP impact** · risk gauge · live reasoning terminal
- Stand-in models are **labelled on screen** — a placeholder score is never shown as evidence

> **Speaker Notes:** The analyst drops an email onto the dashboard. The backend streams an event for every step — protocol forensics, the delivery graph, the detonation, each reasoning token — so the screen fills in as the analysis happens rather than after a spinner. The vision and topology branches run in parallel; in the live system the graph is scored in about ninety milliseconds while the browser is still loading the page. The map colours each edge by whether its subsystem's SHAP contribution pushed the risk up, and the globe in the background draws the delivery route hop by hop, in red above a risk of seventy-five; any hop that could not be geolocated is drawn dashed and counted as an estimate. One design decision I want to point out: whenever an engine is running a stand-in model, the dashboard says so next to the score. A security tool must never present a placeholder number as evidence.

*(Optional 60-second live demo here: drop an `.eml`, narrate the telemetry, point at the edge colours and the SHAP-backed gauge.)*

---

## Slide 7 — Performance Metrics

**On the slide**
- **OOF ROC-AUC 0.855** (5-fold stratified, 2,551 ham / 501 spam)
- Ham P/R **0.90 / 0.95** · Spam P/R **0.63 / 0.48** at threshold 0.5
- **Leakage controls:** out-of-fold scoring · cross-fitted MemAE · SLM verdict held constant (a naive label mapping gave a meaningless AUC of 1.0)
- **Latency:** ≈ 4 s end to end, ≈ 2.5 s of it browser detonation; Tiers 1 + 3 < 100 ms
- **Trade-offs:** JavaScript off (safe, fast; misses JS-only kits) · first URL only · 4 s budget
- **Known gap:** 2002 corpus has no DMARC headers → model under-scores modern lures

> **Speaker Notes:** On the SpamAssassin corpus the system reaches an out-of-fold ROC-AUC of zero point eight five five. Every reported prediction comes from a model that never saw that email, and the graph-anomaly feature is cross-fitted, so the MemAE that scores an email never trained on it. One finding I am proud of: the original training plan mapped ham to a benign verdict and spam to a critical verdict for the language-model feature. That writes the answer into the input; it produces a perfect AUC and a useless model. I removed it, and these are the honest numbers. Recall on spam is zero point four eight at the default threshold, and I know why: the corpus is from 2002, before DMARC existed, and vision and the language model could not run for every training email, so five of the ten features never varied. On a modern lure the trained model scores low — around five out of a hundred. That is a data problem with a clear fix, which is my first item of future work. On latency, a complete assessment takes about four seconds, dominated by the two and a half seconds of browser rendering. The deterministic tiers together take under a hundred milliseconds.

---

## Slide 8 — Future Scope & Conclusion

**On the slide**
- Retrain on a **modern labelled corpus** with authentication headers; run vision + SLM during training
- **Monotonic constraints** so spoofing and route anomalies can only raise risk
- Real **vision model** with brand centroids; credential-form detection
- **Throughput:** pre-warmed browser pool, URL verdict cache, job queue
- Conclusion: **explainable, multimodal, private, and engineered to survive hostile input**

> **Speaker Notes:** The next steps follow directly from the evaluation. Retrain on modern mail with authentication headers, and run the vision and reasoning tiers during training so their features carry signal. Add monotonic constraints, so that out-of-distribution data can never teach the model that a spoofed sender lowers risk. Install a real vision model, and add a browser pool and a verdict cache for throughput. To conclude: Sentinel-Graph moves phishing detection from reading words to examining evidence. It models delivery as a graph and detects unseen routes without labels; it reasons locally, keeping personal data private; and it explains every score. Just as importantly, it is honest about its own limits, down to labelling stand-in models on the screen. Thank you. I am happy to take your questions.

---

## 🛡️ Defense Q&A Armor

### Q1. "Why use a complex MemAE GNN when standard Random Forests or SVMs exist?"

> **Answer:** I do use a Random Forest — it is the fusion model at the top of the system. The two answer different questions. A Random Forest or an SVM is supervised: it needs labelled attacks and learns the patterns those attacks had. The MemAE is unsupervised: it trains on legitimate mail alone and asks only "does this delivery route look like anything normal I have seen?" That is how it can flag a routing trick no one has labelled yet. A flat classifier also cannot see structure. A route is a sequence of connected hops, and the graph convolution lets each hop's representation depend on its neighbours. The memory addresses the classic weakness of autoencoders: without it, the network would learn to reconstruct anomalies too. So the GNN finds the novel; the forest weighs it against everything else. One honest limit: route nodes currently carry only their position, so the trained MemAE models route shape rather than forged hops — on the demo lure its loss is 0.0003 and its SHAP share 11.5%. Per-hop node attributes are the fix; see `CAPSTONE_DEFENSE.md`.

### Q2. "How do you handle the severe latency of spawning a headless browser for every email in a production environment?"

> **Answer:** First, the cost is bounded and measured: about two and a half seconds of a four-second assessment, and it never blocks the other tiers. Detonation runs concurrently with the graph analysis, and the deterministic forensics finish in under a hundred milliseconds, so the analyst sees useful evidence almost immediately. Second, the work is limited by design: only the first link is detonated, JavaScript is disabled, executables and media are never downloaded, navigation has a four-second budget, and a hard deadline guarantees the browser cannot hang the pipeline. Third, for production volume I would add a pool of pre-warmed browsers instead of launching one per email, a cache keyed on the URL so a campaign's thousandth copy costs nothing, and a job queue so mail flow never waits on rendering. Those three are future work, not built yet. The architecture already supports them, because the sandbox is an injected component behind one function.

### Q3. "Why run the SLM locally via ONNX instead of calling the OpenAI / GPT-4 API, which is far more capable?"

> **Answer:** It is more capable, and I do not claim otherwise. The question is what the capability is used for. Here the model writes a short deduction from evidence the other tiers have already extracted, and its verdict is one of ten features, so the marginal accuracy of a frontier model buys little. What a cloud API costs is significant. Every email would leave the organisation — personal data, sent to a third party, which we would have to justify under the DPDP Act and our own retention policies. Reasoning could not be reproduced exactly for an audit. Every analysis would depend on an external service's availability, pricing and model changes. And an attacker could target the provider's model with prompt injection that we cannot inspect. Locally, the data never leaves, decoding is deterministic, and I control the injection defences end to end. To be transparent about the current build: the local inference path is implemented and tested, and the deployed instance runs a flagged stand-in until the Phi-3 model files are installed.

---

### Prepared admissions (say these before you are asked)

- The vision model and the SLM are **stand-ins** in the current deployment; the system labels them on every result.
- The trained model was evaluated on **2002 data** and under-scores modern phishing; this is the top future-work item.
- Results are **out-of-fold on one public corpus**, not a production trial.
