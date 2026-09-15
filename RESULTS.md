# Evaluation Results & Reproduction

This document maps every headline number in the paper to the script that
produces it and the dataset it runs on. The paper has four contributions:

- **C1** — symbolic deobfuscation as a "force multiplier"
- **C2** — calibrated confidence (post-hoc isotonic calibration) and a
  distribution-free conformal risk-control layer with a finite-sample FDR
  guarantee
- **C3** — a small *local* LLM matches cloud-scale LLMs for IOC extraction
- **C4** — an adversarial threat model: the report is untrusted input;
  C2 and a hardened verifier prompt mitigate report-borne false-IOC and
  prompt-injection attacks

## Reproduce everything

```bash
python scripts/reproduce_all.py
```

This runs the full analysis chain **offline** — no Ollama, no API keys, no
network — by reusing the cached LLM predictions in `data/evaluation/`. To
regenerate the cached predictions themselves (the expensive LLM phase), see
[Regenerating the cache](#regenerating-the-cache).

## Datasets

Loaded via `threat_intel_aggregator/evaluation/datasets.py` `load_samples()`.

| Name | Size | Labels | Role |
|---|---|---|---|
| `synthetic` | 122 samples | hand-built | control set |
| `real_world_v2_gpt55` | 134 reports | GPT-5.5 teacher | real-report set |
| `otx` | 400 pulses | OTX indicator lists | scale set |
| `prism` | 50 reports / 1418 IOCs | **human analyst gold** (arXiv:2506.11325) | external gold benchmark |

`benchmark` and `real_world` are **deprecated** (labels not text-grounded — see
`DEPRECATED_DATASETS` in `datasets.py`).

## Headline numbers

| Contribution | Number | Script | Output artifact |
|---|---|---|---|
| C1 | Deobfuscation ON is tier-invariant; OFF collapses to 0% at T3/T4; held-out adversarial T5 is non-circular | `run_obfuscation_ablation.py --dataset prism` | `obfuscation_ablation_prism.json` |
| C1 | Off-the-shelf baselines (ioc-finder, iocextract, regex) vs our pipeline across the same obfuscation tiers — do tools that win on clean text (T0) collapse under obfuscation (T2+) the same way ours does without deobfuscation? | `run_obfuscation_baselines.py --dataset prism` | `obfuscation_baselines_prism.json` |
| C1 | Hybrid compositions: our deobfuscation layer and candidate filters applied to `ioc-finder`'s output, with a *paired* bootstrap delta against both extractors at every tier | `run_hybrid_study.py --dataset prism` | `hybrid_study_prism.json` |
| C2 | Calibration metrics with bootstrap CIs; raw LLM is badly miscalibrated, isotonic fixes it (ECE → ~0.02 on gold) | `run_calibration_study.py --dataset <name>` | `calibration_study_<name>.json` |
| C2 | Production calibrator (pooled) and a PRISM-held-out calibrator | `fit_calibrator.py [--exclude-dataset prism]` | `fitted_calibrator[_no_prism].json` |
| C3 | Local Qwen vs GPT-5.5 / Claude / Gemini 3 Flash on PRISM gold, F1 ± CI | `multi_model_benchmark.py --dataset prism` | `multi_model_benchmark_prism.json` |
| C2 | Selective-prediction triage: risk-coverage curve, AURC per confidence source, target-risk operating points | `selective_prediction.py --dataset prism --calibrator …_no_prism.json` | `selective_prediction_prism.json` |
| C2 | Calibration transfer: train-by-test ECE matrix across report sources | `calibration_transfer.py` | `calibration_transfer.json` |
| C2+ | Conformal risk control: FDR-vs-coverage table per confidence source with a finite-sample guarantee, plus a cross-source transfer matrix | `run_conformal_study.py` | `conformal_study_<name>.json`, `conformal_transfer.json` |
| C4 | Adversarial threat model: report-borne false-IOC attack success before/after the C2 threshold, and verifier prompt-injection neutralisation before/after the hardened defense | `run_adversarial_study.py --dataset prism` | `adversarial_study_prism.json` |
| End-to-end | Full-pipeline P/R/F1 vs threshold on PRISM gold (max F1 + honest τ=0.5 operating point) | `eval_pipeline_f1.py --dataset prism --calibrator …_no_prism.json` | `pipeline_f1_prism.json` |
| Baselines | Our pipeline vs iocextract / ioc-finder / spaCy / regex on PRISM gold, F1 ± CI | `run_gold_benchmark.py --dataset prism` | `gold_benchmark_prism.json` |

All confidence intervals are 95% percentile bootstrap (`bootstrap_ci.py`,
`bootstrap_calibration_ci` in `calibration.py`), `seed=42`, 1000 resamples.
System-vs-system comparisons additionally use a **paired** bootstrap
(`compute_paired_bootstrap_delta`), which resamples report indices once and
scores both systems on the same resample; marginal intervals overlap on
comparisons the paired test resolves.

### C1 hybrid: what the pipeline actually contributes

`run_hybrid_study.py` composes the pipeline with `ioc-finder` instead of
ranking them. F1 on PRISM gold, flat across T0–T4 unless noted:

| Configuration | T0 clean | T3/T4 | T5 held out |
|---|---|---|---|
| Our pipeline (regex + deobfuscation) | 0.7449 | 0.7449 | 0.3628 |
| `ioc-finder` alone | 0.8296 | 0.4895 | 0.4893 |
| `ioc-finder` on deobfuscated text | 0.8182 | 0.8182 | 0.4638 |
| … plus our validity/blocklist filters | 0.8393 | 0.8393 | 0.4417 |
| … minus the URL-domain dedup rule | **0.8488** | **0.8488** | 0.4875 |
| Plain union of both candidate sets | 0.7454 | 0.7454 | 0.4142 |

Paired against `ioc-finder` on the same 50 reports, the last configuration
gains 0.0192 [0.0039, 0.0372] on clean text (p=0.010), 0.3593 [0.2559, 0.4742]
at T3/T4, and is indistinguishable at T5 (−0.0018, p=0.81). Paired against our
own extractor it gains 0.1039 at T0–T4 and 0.1247 at T5. Keeping the dedup rule
(the 0.8393 row) leaves the composition ahead at every tier but not
significantly so on clean text (+0.0097, p=0.61) — the conservative reading,
and the configuration the abstract quotes.

Three things this settles:

- **Candidate generation is not our contribution.** The plain union scores
  *below* `ioc-finder` alone: our regex layer adds 332 false positives and 2
  true positives on top of it.
- **Deobfuscation and the filters are, and both transfer** to a third-party
  extractor that never had them.
- **The 0.8639 extraction-recall ceiling is a regex-coverage limit, not a
  deobfuscation limit.** The composition recalls 0.9697.

The URL-domain dedup rule drops a bare domain already contained in an
extracted URL; PRISM labels those as two indicators, so on this benchmark the
rule is a schema mismatch (−112 TP, −197 FP) rather than a precision gain.

**Version provenance.** All headline numbers use `ioc-finder==9.4.1` (released
2026-06-17, the current release; pinned in `requirements.txt`, which previously
did not list the tool at all). `iocextract==1.16.1` is also the current release.

The study was first run against `ioc-finder==7.3.0` (Dec 2022), which was what
happened to be installed. The collapse is not specific to a version — on 7.3.0,
`ioc-finder` scores 0.8331 clean and 0.4922 at T3, and the composition 0.8532 —
but benchmarking a four-year-old release against a 2026 paper is not
defensible, so everything was re-based. The 7.3.0 run is kept as
`hybrid_study_prism_iocfinder730.json` for provenance; to reproduce it without
disturbing the pinned environment:

```bash
pip install --target /tmp/if73 "ioc-finder==7.3.0"
PYTHONPATH=/tmp/if73 python scripts/run_hybrid_study.py --dataset prism \
  --output data/evaluation/hybrid_study_prism_iocfinder730.json
```

Re-basing changed `obfuscation_baselines_prism.json`, `gold_benchmark_prism.json`,
`hybrid_study_prism.json`, and `fig_obfuscation_collapse.pdf`; `regex_only`,
`our_pipeline`, and `iocextract` are unaffected.

## Regenerating the cache

The cached predictions (`data/evaluation/calibration_predictions_*.json`,
`multi_model_benchmark_prism.json`) come from the expensive LLM phase:

- **Local (Ollama)** — `run_calibration_study.py --dataset <name> --fresh`
  requires Ollama running with the verifier model pulled.
- **Cloud** — `multi_model_benchmark.py` and `build_real_world_dataset.py`
  need `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` in a
  repo-root `.env` file. `multi_model_benchmark.py --models <name> --merge`
  benchmarks one model and splices its row into the existing file (the other
  models' rows stay byte-identical). Each model run checkpoints every LLM
  verdict to a `llm_verify_cache_<dataset>_<model>.jsonl` file, so a run
  interrupted by a rate limit resumes from where it stopped on re-invocation;
  delete that file to force a fresh run.
- **PRISM** — `prism_benchmark.json` is regenerated from a LANCE clone with
  `build_prism_dataset.py` (PRISM is GPL-3.0; the file is not vendored).

## Verification

`python -m pytest tests/ -q` — the full suite must stay green.
