# Sentinel-Graph (SOC v2) — 5-Minute Defense Script & Q&A Armor

**Presenter:** Uday Babasaheb Baviskar · B.E. Information Technology · JSPM Jayawantrao Sawant College of Engineering
**Format:** 8 slides · 5 minutes (≈35–40 s per slide, ≈90 spoken words each) · the 12-minute version is [`CAPSTONE_PRESENTATION.md`](CAPSTONE_PRESENTATION.md)
**Rule:** every number here was measured on this codebase (training report, test suite, or `pytest tests/e2e/test_capstone_defense.py -s`). Quote them exactly. If an examiner asks for a number that is not on this page, say you have not measured it.

> **Naming note.** The brief's phrase "cyber-kinetic graphs" means attacks with physical effects (grids, industrial control) in security literature; an examiner can challenge it. Say **delivery-topology graphs**.

---

## 📇 Facts card

| | |
|---|---|
| OOF ROC-AUC · 5-fold stratified · SpamAssassin 2002 (2,551 ham / 501 spam) | **0.855** |
| Spam P / R @ 0.5 · Ham P / R | 0.634 / 0.477 · 0.902 / 0.946 |
| MemAE | GCN 5→32→16 · memory 50×16 · τ = 0.1 · λ = 0.05 · zero-day threshold **0.913** (99th pct. of out-of-fold benign loss) |
| Latency, laptop CPU | Tier 1 ≈ 60 ms · topology ≈ 90 ms · detonation ≈ 2.5 s · full assessment ≈ 4 s |
| Sandbox bounds | 4 s navigation budget · hard deadline 2 × 4 s + 15 s start-up = **23 s** worst case |
| Tests | **310 passed** (1 live-network test opt-in) |
| Demo lure, trained models | risk **15/100** · `private_ip_leak` SHAP **−0.129** · MemAE loss **0.0003** |
| Modern corpus | 1,000 phishing emails (Nazario 2023–25, CC-BY-4.0) · benign half pending |
| Stand-ins (flagged on screen) | vision model · SLM (always answers CRITICAL) · globe positions for unlocatable hops |

---

## Slide 1 — The Evasion Problem

**On the slide**
- TF-IDF scores the words — the part of an email the attacker controls best
- LLM-written lures are unique per target: no repeated n-grams to learn
- Homoglyphs (`аpple` with Cyrillic а), zero-width splits, image-only bodies defeat tokenisers
- What the attacker **cannot** cheaply change: authentication results, delivery route, what the link renders

> **Speaker Notes:** A TF-IDF classifier weighs words by how often they appear in one email and how rare they are across the corpus. That works when attackers reuse text. Modern operations don't: a language model writes a fresh lure per victim, brand names use Cyrillic look-alike letters, and invisible zero-width characters split the words a tokeniser would match. So the classic model reads exactly the part of the email the attacker controls best. Sentinel-Graph looks instead at evidence that is expensive to fake: did the sender authenticate, how was the mail delivered, and what does the link actually render.

---

## Slide 2 — From Text to Delivery-Topology Graphs

**On the slide**
- Email → DAG: **sender → relay hops → receiver**, **sender → each URL**
- Node features `x ∈ ℝ^{N×5}`: one-hot type ‖ path position or URL entropy
- 2 × GCN → latent `z`, rebuilt from a **memory of 50 normal prototypes**: `ẑ = ŵM`
- Trained on **benign mail only** → flags routes it has never seen, with no attack labels
- Receiver-side hops stripped: the model scores the **sender's** path, not the victim's mailbox

> **Speaker Notes:** Each email becomes a small directed graph of its delivery. Two graph-convolution layers embed every node, and then the key step: each embedding must be rebuilt from a sparse mix of fifty learned prototypes of normal delivery. A route the memory has never seen cannot be rebuilt, so its reconstruction error rises — that error is the anomaly score, and it needs no labelled attacks. One subtle fix matters here: hops added by the *recipient's* provider are stripped first. Otherwise a model learns which mailbox an email came from, not whether it is phishing.

---

## Slide 3 — Tiers 1 & 2: Protocol Forensics & Headless Sandboxing

**On the slide**
- **Tier 1 (~60 ms):** hardened MIME · SPF/DKIM/DMARC/ARC from the *trusted* header only · private hop between public hops · backwards timestamps · homoglyph-folded display-name spoofing
- **Tier 2 (~2.5 s):** fresh headless Chromium per URL · JavaScript off · downloads refused · executables/archives/media blocked
- **Egress proxy:** every connection, redirects included, may reach only public IPs (blocks `169.254.169.254`)

> **Speaker Notes:** Tier one is deterministic. Authentication results are read only from the header our own server wrote, with comments blanked, because senders can inject text into lower ones. The route analyser flags a private address between public hops and clocks that run backwards. Tier two opens the link in a throwaway browser with scripts disabled. While building it I found that Playwright's routing never sees redirects, so a page could bounce the sandbox to the cloud metadata service. Every connection now passes an egress proxy that only connects to public addresses.

---

## Slide 4 — Explainable AI: SHAP + Random Forest Meta-Scorer

**On the slide**
- 10 features from 4 subsystems → **Random Forest** → phishing probability
- **TreeSHAP:** exact, additive — `base value + Σ φᵢ = p` (tested to 10⁻⁶)
- Attribution per feature **and** per subsystem; map edges coloured by sign of φ
- The explanation exposes the model's own mistakes (Slide 7)

> **Speaker Notes:** Every tier produces numbers, and a Random Forest fuses them into one probability. A score alone is not enough for an analyst, so TreeSHAP decomposes it exactly: the base rate plus each feature's contribution equals the prediction, and the test suite checks that to six decimal places. The dashboard shows each contribution and colours the delivery map by whether that subsystem pushed risk up or down. As you'll see on the metrics slide, this is also how I caught the model learning something wrong.

---

## Slide 5 — The Edge Inference Advantage: Local ONNX SLM vs Cloud APIs

**On the slide**
- ONNX Runtime GenAI, Phi-3-mini slot (int4 ≈ 2.5 GB) — runs on the analyst's host
- **No email leaves the machine** (DPDP Act, 2023) · **greedy decoding** → reproducible for audit
- Injection-hardened prompt · extracted verdict **escalates, never downgrades**
- Streamed token by token over the same WebSocket
- **Status:** inference path built and tested; demo runs a flagged scripted stand-in

> **Speaker Notes:** The reasoning model writes a short forensic deduction. It runs locally, because an email is personal data and sending it to a cloud model is a transfer we'd have to justify under India's data-protection law. Greedy decoding makes the same evidence produce the same text, so a verdict can be reproduced in an audit. The prompt neutralises anything that could forge our section markers or the verdict line. To be precise: the ONNX path is implemented and tested, and today's demo runs a clearly labelled stand-in until the model files are installed.

---

## Slide 6 — The 3D WebGL Dashboard & Privacy-Aware IP Mapping

**On the slide**
- React 19 + Zustand + React Router: **Live** and **History** pages; canvas and socket live outside the routes — switching pages never kills a scan
- Wireframe globe, hop-to-hop Bézier arcs — red above risk 75
- Geo lookup with a **deterministic FNV-1a fallback**; estimated hops drawn **dashed** and counted
- Private IPs never sent · `VITE_GEO_LOOKUP=off` → fully offline
- Every scan persisted with its IPs, URLs and domains → **pivot** to every scan that saw an indicator

> **Speaker Notes:** The dashboard streams every step as it happens. The delivery route is drawn hop by hop on a globe. Public IPs are geolocated; if the lookup fails or is rate-limited, the IP is hashed to a stable stand-in position, drawn dashed and counted on screen — an estimate is never shown as a real location. Private addresses are never sent anywhere, and one switch makes the globe fully offline. Every verdict is saved with its indicators, so from one IP the history API finds every other email in the campaign.

---

## Slide 7 — Metrics: OOF ROC-AUC & Modern Dataset Bootstrapping

**On the slide**
- **OOF ROC-AUC 0.855** · leakage controls: out-of-fold scoring · cross-fitted MemAE · SLM feature held constant (a naive label mapping gave a fake AUC of 1.0)
- Spam recall **0.48** @ 0.5 — 2002 corpus has no DMARC; 5 of 10 features constant
- **Demo lure scores 15/100:** SHAP shows `private_ip_leak` *lowering* risk (−0.129)
- MemAE models route *shape*: forged 3-hop route 0.0003 vs benign 1-hop + link 0.96
- Modern corpus pipeline: 1,000 phishing (2023–25) downloaded; benign mailbox pending

> **Speaker Notes:** Out of fold, the system reaches a ROC-AUC of 0.855, and every prediction comes from a model that never saw that email. I removed a label leak from the original plan that produced a perfect, meaningless score. Recall is weak, and SHAP shows why: on a modern lure, the private-IP feature *lowers* risk — because two-thirds of the legitimate training mail is mailing-list traffic, which really does pass through private corporate relays. And the graph model learned route length, not forgery. "Bootstrapping" here means building the dataset: the modern phishing half is downloaded; the benign half needs a consented mailbox export.

---

## Slide 8 — Conclusion & Future Scope

**On the slide**
- **Retrain** on the modern corpus with authentication headers; run vision + SLM during training
- **Monotonic constraints:** spoofing, IP-leak and clock features may only *raise* risk
- **Per-hop node attributes** (bogon flag, ASN change, clock delta, rDNS agreement) so the GNN sees forgery
- Real vision model · warm browser pool + URL cache for throughput
- Explainable · multimodal · private · honest about its own limits

> **Speaker Notes:** Each next step comes straight from the evaluation. Retrain on modern mail; constrain the forest so evidence of spoofing can only raise risk; give each graph node its own attributes so the anomaly model can see a forged hop, not just a long route. To conclude: Sentinel-Graph moves detection from reading words to examining evidence, explains every score, keeps data on the host, and — as the last two slides show — tells you exactly where it is still wrong. Thank you.

---

## 🛡️ Defense Q&A Armor

### Q1. "Why use a complex GNN when standard Random Forests exist?"

> **Answer:** I use both, for different learning problems. The Random Forest is the fusion layer: a supervised discriminator that estimates *p(phishing | features)* and therefore needs labelled examples of each attack pattern. The MemAE is one-class: it is trained only on benign routes and scores how well a route can be reproduced from what normal looks like, so it needs no attack labels at all.
>
> The memory is what makes that work mathematically. The addressing weights are non-negative and re-normalised to sum to 1, so the rebuilt latent ẑ = ŵM is a **convex combination** of memory rows: it can only lie in the convex hull of the 50 learned prototypes, and hard shrinkage at λ = 0.05 restricts it to a face spanned by a few of them. A plain autoencoder has no such constraint and learns to reconstruct anomalies too; here a latent outside the hull of normal behaviour cannot be reproduced, so the BCE between predicted and true adjacency rises. Structurally, a forest needs a fixed-length vector, while a route has a variable number of hops; the GCN propagation D̂^{-½}ÂD̂^{-½}HW shares weights across nodes, so the same 5→32→16 parameters handle any route length; the layers are permutation-equivariant and the adjacency loss is permutation-invariant, so node ordering cannot change the score.
>
> The honest limit, which I measured: today a route node's features are only its type and path position. So the trained MemAE models the *shape* of delivery — a forged three-hop route scores 0.0003 while a benign one-hop email with a link scores 0.96. It detects unusual route lengths and link profiles, not forged hops. The fix is to give every hop node its own attributes — private-range flag, ASN change, clock delta, reverse-DNS agreement — and the experiment that settles your question is an ablation: fusion AUC with and without the MemAE feature. I have not run that ablation yet.

### Q2. "How do you handle the latency of headless browsers in a production SOC?"

> **Answer:** First, it never blocks the other evidence. Tier 1 finishes in about 60 ms; detonation and topology run concurrently under `asyncio.gather`, and topology is scored in about 90 ms while the browser is still loading. The analyst sees authentication, route and graph results almost immediately; the screenshot arrives at about 2.5 s of a 4 s assessment.
>
> Second, the cost is bounded by construction. Only the first URL is detonated; JavaScript is off, so there is no script execution time; executables, archives and media are aborted at the routing layer; navigation and image loading share one 4 s budget (whatever DOM loading leaves is spent waiting for logos); and an `asyncio` hard deadline of 2 × 4 s + 15 s start-up = 23 s guarantees a hung browser can never stall the pipeline — the branch returns `None` and the score is computed without vision.
>
> Third, throughput at SOC volume is a queueing problem, and the arithmetic is simple. With *k* warm browser contexts and a service time *s* ≈ 2.5 s, capacity is *k/s* detonations per second: 8 contexts ≈ 3.2/s ≈ 11,500 per hour. Phishing campaigns reuse URLs, so a URL-keyed result cache with hit rate *h* cuts the arrival rate to λ(1 − *h*); by Little's law the queue length is L = λ(1 − *h*)·W. Those three pieces — a warm pool, the cache, and a job queue so mail flow never waits — are future work. The trade-off to name: today each URL gets a fresh browser *process*; a pool reuses the process and isolates with per-URL contexts, which is cheaper but shares one renderer sandbox.

### Q3. "Why run a quantized SLM locally instead of calling the OpenAI / GPT-4 API?"

> **Answer:** A frontier model is more capable, and I don't claim otherwise. The question is what that capability would buy here, and what it would cost.
>
> What it would buy is small. The SLM reasons over evidence the deterministic tiers have already extracted, and its verdict is one of ten fusion features. In the shipped model that feature was deliberately held constant during training — mapping ham to BENIGN and spam to CRITICAL would have leaked the label and produced a fake AUC of 1.0 — so it currently carries zero weight in the score. Swapping in GPT-4 today would change the analyst's narrative, not the risk number.
>
> What it would cost is structural. Every email would leave the organisation: personal data transferred to a third party, which must be justified under the DPDP Act 2023 and our retention policy. Sampling-based APIs are not bit-reproducible, and the vendor can change the model under us, so a verdict could not be re-derived for an audit; local greedy decoding gives the same tokens for the same input. Cost scales per token with mail volume, while a local int4 Phi-3-mini is a fixed ~2.5 GB on hardware we already own. And prompt-injection defences are only as good as what you can inspect: locally I control the whole template — the payload is folded to one line, section markers and chat-role tokens are neutralised, and the extracted verdict can escalate but never downgrade. Current state, stated plainly: the ONNX inference path is implemented and tested against the library's API; the demo runs a flagged scripted stand-in.

### Q4. "What happens if your Geo-IP API rate-limits or blocks you during a live demo?"

> **Answer:** Nothing visible breaks, and nothing false is shown. `resolveIPsToCoords` returns `Promise.all` over per-IP lookups, and each lookup catches its own failure, so the whole call can never reject. Every failure mode maps to the same fallback: network or CORS errors, HTTP 429, ipapi's `200 {"error": true}` refusal, and a 4 s `AbortSignal.timeout`. Lookups are cached per session as promises, so repeating the demo, or two hops with the same IP, costs one request, which keeps us under the free tier's limit in the first place.
>
> The fallback is deterministic: 32-bit FNV-1a with two independent seeds, mapped to `lat = (h₁ mod 18001)/100 − 90` and `lng = (h₂ mod 36000)/100 − 180`. The same IP always lands on the same point, so the demo is reproducible. That is an 18,001 × 36,000 grid of about 6.5 × 10⁸ cells, so by the birthday bound the chance that two of *n* hops collide is about n²/(2 × 6.5 × 10⁸): under 10⁻⁷ for a ten-hop route. The renderer is also guarded against the geometric edge cases: coincident hops produce no arc instead of a zero-length curve, and antipodal hops use a perpendicular great circle instead of normalising a zero vector into NaN.
>
> Most importantly, an estimated point is **never** presented as a location. Each point is tagged `lookup` or `estimated`; estimated arcs are dashed white and the risk gauge prints how many hop locations are stand-ins. Private and reserved IPs are never sent at all, and if the venue has no network — or I prefer not to send indicators to a third party — `VITE_GEO_LOOKUP=off` makes the whole globe offline before the demo starts.

---

### Hard follow-up: "So what does your GCN actually learn beyond hop count?"

> **Answer:** Today, mostly route shape: path length, how many links hang off the sender, and those links' character entropy. I measured it: the forged three-hop demo route scores 0.0003, a benign single-hop email with one link scores 0.96. The private-IP and backwards-clock evidence currently reaches the score as separate fusion features, not through the graph. Per-hop node attributes are the next change, and that is what would let the memory learn what a *normal hop* looks like rather than a normal route length.

### Prepared admissions (say these before you are asked)

- The vision model and the SLM are **stand-ins**; the API and dashboard label them on every result. The SLM stand-in always answers CRITICAL, so the history log shows CRITICAL even for benign mail.
- The shipped models were trained on **2002 data**; the demo lure scores 15/100 and `private_ip_leak` is inverted. Monotonic constraints and modern retraining fix the cause, not the symptom.
- The MemAE sees **route shape, not hop attributes** (see the follow-up above).
- All results are **out-of-fold on one public corpus**, not a production trial. No ablation or confidence interval for the AUC has been computed yet.
