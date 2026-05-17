# Evaluation Results & Reproduction

This document maps every headline number in the paper to the script that
produces it and the dataset it runs on. The paper has three contributions:

- **C1** — symbolic deobfuscation as a "force multiplier"
- **C2** — calibrated confidence fusion (post-hoc isotonic calibration)
- **C3** — a small *local* LLM matches cloud-scale LLMs for IOC extraction

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
| C2 | Calibration metrics with bootstrap CIs; raw LLM is badly miscalibrated, isotonic fixes it (ECE → ~0.02 on gold) | `run_calibration_study.py --dataset <name>` | `calibration_study_<name>.json` |
| C2 | Production calibrator (pooled) and a PRISM-held-out calibrator | `fit_calibrator.py [--exclude-dataset prism]` | `fitted_calibrator[_no_prism].json` |
| C3 | Local Qwen vs GPT-5.5 / Claude on PRISM gold, F1 ± CI | `multi_model_benchmark.py --dataset prism` | `multi_model_benchmark_prism.json` |
| C2 | Selective-prediction triage: risk-coverage curve, AURC per confidence source, target-risk operating points | `selective_prediction.py --dataset prism --calibrator …_no_prism.json` | `selective_prediction_prism.json` |
| C2 | Calibration transfer: train-by-test ECE matrix across report sources | `calibration_transfer.py` | `calibration_transfer.json` |
| End-to-end | Full-pipeline P/R/F1 vs threshold on PRISM gold (max F1 + honest τ=0.5 operating point) | `eval_pipeline_f1.py --dataset prism --calibrator …_no_prism.json` | `pipeline_f1_prism.json` |
| Baselines | Our pipeline vs iocextract / ioc-finder / spaCy / regex on PRISM gold, F1 ± CI | `run_gold_benchmark.py --dataset prism` | `gold_benchmark_prism.json` |

All confidence intervals are 95% percentile bootstrap (`bootstrap_ci.py`,
`bootstrap_calibration_ci` in `calibration.py`), `seed=42`, 1000 resamples.

## Regenerating the cache

The cached predictions (`data/evaluation/calibration_predictions_*.json`,
`multi_model_benchmark_prism.json`) come from the expensive LLM phase:

- **Local (Ollama)** — `run_calibration_study.py --dataset <name> --fresh`
  requires Ollama running with the verifier model pulled.
- **Cloud** — `multi_model_benchmark.py` and `build_real_world_dataset.py`
  need `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` in a
  repo-root `.env` file.
- **PRISM** — `prism_benchmark.json` is regenerated from a LANCE clone with
  `build_prism_dataset.py` (PRISM is GPL-3.0; the file is not vendored).

## Verification

`python -m pytest tests/ -q` — the full suite must stay green.
