# Literature Review — Automated CTI / IOC Extraction (2025–2026)

> Compiled 2026-05-15 for the research-paper effort. Scope: IOC extraction, IOC
> deobfuscation/defanging, LLM-based CTI extraction & benchmarking, CTI knowledge
> graphs and graph-based campaign reasoning. Venue quartiles are approximate
> (SJR/JCR) and should be re-verified before citing.

---

## 1. LLM-based CTI / IOC extraction

### Large Language Models are Unreliable for Cyber Threat Intelligence
- **Authors / venue:** Mezzi, Massacci, Tuma — ARES 2025 (CORE B conference); arXiv:2503.23175.
- **Method:** 5-step pipeline testing GPT-4o, Gemini-1.5-pro, Mistral-large-2 on CTI
  information extraction and generation; zero-shot / few-shot / fine-tuning; measures
  consistency (bootstrapped CIs) and calibration (Expected Calibration Error, Brier Score).
- **Dataset:** 350 MITRE ATT&CK threat reports, ~3,009 words avg, 86 APT groups, STIX-formatted.
- **Findings:** Zero-shot recall only 0.58–0.90; **few-shot and fine-tuning often *worsen*
  results** (APT recall 0.87→0.68 after fine-tuning); models **severely miscalibrated**
  (ECE up to 0.91); non-deterministic across re-prompts.
- **Open problems:** poor calibration in security-critical settings; need for CoT, RAG,
  multi-agent approaches; few labelled datasets where confidence matters.
- **Relevance:** Anchor citation for our **calibrated confidence fusion** contribution.

### Benchmarking LLMs for IoC Recovery under Adversarial Code Obfuscation and Encryption
- **Authors / venue:** Morales, Pastrana, Tapiador (UC3M Madrid) — arXiv (2025/26), conference submission.
- **Method:** 336 JS programs → 12 progressive obfuscation transforms (Base64 → AES-256 +
  structural) → 4,368 variants, each embedding an IP-as-IOC; queries 5 LLMs (ChatGPT,
  Gemini, Claude 3 Sonnet, Grok-2, Command-R7B) for YES/NO/DON'T-KNOW IOC presence.
- **Metrics:** detection rate, extraction accuracy, FP/FN, hallucination rate (0–4.8%), uncertainty rate.
- **Findings:** ~100% detection at phases 0–4; **performance collapses to ~95%+ failure once
  encryption is introduced** — LLMs lack symbolic reasoning about cryptographic operations.
- **Open problems:** no symbolic decoding/cross-transformation reasoning; polymorphic/
  metamorphic obfuscation excluded; commercial-snapshot evaluation only.
- **Relevance:** Closest prior work. Ours differs — *text/defanging* obfuscation (not code),
  and we position symbolic deobfuscation as the missing piece they identify.

### SoK: Automated TTP Extraction from CTI Reports — Are We There Yet?
- **Authors / venue:** Büchel et al. (UTwente / van Ede, Continella) — **USENIX Security 2025** (top-tier).
- **Method:** systematizes 40+ TTP-extraction papers (NER → embedder → generative LLM).
- **Findings:** existing approaches hit a **performance ceiling**; **traditional NLP often
  beats embedder/generative LLMs in realistic settings**; datasets are custom, inaccessible,
  non-comparable; TTP ontologies carry inherent ambiguity.
- **Relevance:** Anchor citation — motivates standard benchmarks and tempers LLM hype.

### IntelEX / CyberRE-LLM / TIEF (supporting)
- **IntelEX** (arXiv:2412.10872) — LLM-driven attack-level threat intelligence extraction.
- **CyberRE-LLM** (ICIC 2025, Springer) — CTI relation extraction; consensus prompt ensemble,
  multi-candidate disambiguation, self-correction.
- **TIEF** (*Journal of Cybersecurity and Privacy*, MDPI, ~Q2/Q3, 2025) — autonomous IOC
  extraction from heterogeneous reports, STIX 2.1 output.

---

## 2. IOC deobfuscation / defanging / normalization

- **IETF draft `draft-grimminck-safe-ioc-sharing`** (2025) — a proposed standard for
  *consistent, reversible* defanging/refanging of URLs, IPs, emails, domains. Signals the
  community sees inconsistent defanging as an open interoperability problem — useful
  motivation for our deobfuscation contribution.
- **Operational IOC-pipeline practice (2026 industry write-ups)** — normalization =
  Punycode handling, RFC-compliant URL parsing, scheme/host case-folding, canonical form;
  deduplication depends on it.
- **Gap:** no peer-reviewed *learned* or *adversarially-evaluated* deobfuscation system; all
  practice is rule-based and ad hoc. Our 14-stage symbolic deobfuscator + a severity-graded
  obfuscation benchmark is a genuine white space.

---

## 3. CTI knowledge graphs & graph-based campaign reasoning

### CTINexus — Optimized LLM In-Context Learning for CSKG Construction under Data Scarcity
- **Venue:** IEEE EuroS&P 2025; arXiv:2410.21060.
- **Method:** 3 phases — (1) security triplet extraction via optimized ICL with automatic
  demonstration retrieval, (2) hierarchical entity alignment (coarse grouping + fine
  clustering), (3) long-distance relation prediction connecting disjoint subgraphs.
- **Dataset / metrics:** 150 real CTI reports from 10 platforms; entity alignment F1 > 99%,
  long-distance relation F1 ≈ 91%; demonstrates LLM "recency bias" in ICL ordering.
- **Relevance:** SOTA for KG construction; our co-occurrence star-topology KG is simpler —
  do not over-claim on the KG side.

### CTI-Thinker — LLM-driven CTI KG Construction & Attack Reasoning
- **Venue:** *Cybersecurity* (Springer), ~Q2, 2025.

### Other 2025 KG work
- **Network attack knowledge inference** — GCN + 2D KG embeddings — *Scientific Reports* (Nature), Q1/Q2.
- **ICSThreatQA** — KG-enhanced QA for ICS threat intel — ***Expert Systems with Applications*, Q1**, 2025.
- **CyberKG** — SecureBERT_Plus-based CSKG — *Informatics* (MDPI).
- **LLM-CAKG** — automated attack KG construction — ACM conf. 2025.
- Consensus across these: multi-hop / causality-aware reasoning over CTI KGs is an active
  frontier; cross-report attribution remains weak.

---

## 4. Benchmarks & evaluation

- **CTIBench** — NeurIPS 2024 D&B — 6 CTI tasks (knowledge, attribution, severity, etc.).
  Strong candidate as our standard external benchmark.
- **AthenaBench** (arXiv:2511.01144, 2025) — *dynamic* benchmark generated from live MITRE
  ATT&CK + NVD APIs; 6 tasks. Finds reasoning-intensive tasks weak (attribution 39%,
  mitigation 32% F1); notes **no CTI-specialized models exist**.
- **CyberSOCEval** (Meta, arXiv:2509.20166, 2025) — malware analysis + TI reasoning;
  reasoning models get **no test-time-scaling boost** in security.
- **SSNER** (*Symmetry*, MDPI, Q1/Q2, 2025) — segment-level BERT NER for multi-token IOC entities.

---

## 5. Synthesis — recurring gaps (our opportunity)

1. **Calibration & trust.** LLM confidence is unreliable/miscalibrated (Mezzi). No CTI work
   reports ECE/Brier for IOC *extraction* confidence → our calibrated fusion is novel.
2. **Robustness under obfuscation.** LLM extraction collapses under encoding/encryption
   (Morales); symbolic deobfuscation as a recovery layer is unstudied for text/defanging.
3. **No comparable benchmarks.** Every paper rolls its own dataset (USENIX SoK) → a
   severity-graded obfuscation benchmark is itself a contribution.
4. **Cloud-LLM dependence.** Nearly all SOTA uses GPT-4o/Gemini; privacy-preserving small
   *local* LLMs for CTI are essentially unstudied.
5. **No predictive evaluation.** KG/forecasting papers rarely validate predictions against
   later-observed ground truth.

**Chosen paper** addresses gaps 1, 2, 3, 4 — see `memory/research-paper-direction.md`.

---

## Source URLs
- https://arxiv.org/html/2503.23175 — LLMs Unreliable for CTI (ARES 2025)
- https://arxiv.org/html/2605.06910 — Benchmarking LLMs for IoC Recovery under Obfuscation
- https://www.usenix.org/conference/usenixsecurity25/presentation/buechel — SoK TTP Extraction
- https://arxiv.org/abs/2410.21060 — CTINexus (EuroS&P 2025)
- https://link.springer.com/article/10.1186/s42400-025-00505-y — CTI-Thinker (Cybersecurity, Springer)
- https://arxiv.org/html/2511.01144v1 — AthenaBench
- https://arxiv.org/abs/2509.20166 — CyberSOCEval (Meta)
- https://www.sciencedirect.com/science/article/abs/pii/S0957417425037959 — ICSThreatQA (ESWA)
- https://www.mdpi.com/2073-8994/17/5/783 — SSNER (Symmetry)
- https://www.mdpi.com/2624-800X/5/3/63 — TIEF (J. Cybersecurity & Privacy)
- https://arxiv.org/html/2412.10872v1 — IntelEX
- https://link.springer.com/chapter/10.1007/978-981-96-9994-0_22 — CyberRE-LLM
- https://www.nature.com/articles/s41598-025-17941-y — Network attack knowledge inference
- https://www.ietf.org/archive/id/draft-grimminck-safe-ioc-sharing-00.html — Safe IOC Sharing draft
- https://proceedings.neurips.cc/paper_files/paper/2024/file/5acd3c628aa1819fbf07c39ef73e7285-Paper-Datasets_and_Benchmarks_Track.pdf — CTIBench
