"""
Adversarial threat-model study (research-paper contribution C4).

A threat report is untrusted input. This study poisons the PRISM gold reports
with the three attack classes in `evaluation/adversarial_generator.py` and
measures attack success with and without the pipeline's mitigations.

  A1_flood / A2_inject — report-borne false-IOC attacks. Benign attacker-chosen
      indicators are written into the report (flooding to dilute, or framed as
      C2 to poison a blocklist). Regex extraction takes any IOC-shaped string,
      so attack success before mitigation is high; the C2 calibrated-confidence
      threshold (conformal, fitted on clean PRISM) is the filter that rejects
      the low-confidence injected indicators. Genuine-IOC recall is reported
      too, to show the attack adds false positives rather than breaking
      extraction.

  A3_prompt — verifier prompt injection. The payload corpus is scored for the
      share of payloads still carrying a recognisable injection directive after
      the production `sanitize_for_prompt` filter vs. after the new
      `harden_verifier_context` defense.

    python scripts/run_adversarial_study.py --dataset prism

Fully offline — regex extraction plus string-level defense checks, no LLM and no
network. Output is written to data/evaluation/adversarial_study_<dataset>.json.
"""
import argparse
import json
import os
import random
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.adversarial_generator import (
    INJECTION_PAYLOADS, build_adversarial_samples,
)
from threat_intel_aggregator.evaluation.adversarial_defense import (
    harden_verifier_context, is_neutralized,
)
from threat_intel_aggregator.evaluation.conformal import conformal_threshold
from threat_intel_aggregator.evaluation.datasets import load_samples
from threat_intel_aggregator.feed_collection.ioc_extractor import (
    extract_iocs_with_confidence,
)
from threat_intel_aggregator.feed_collection.llm_ioc_verifier import (
    sanitize_for_prompt,
)

C2_ALPHA = 0.10          # target error rate the conformal threshold was fitted to
C2_DELTA = 0.10
N_FLOOD = 8              # decoys injected per report for A1
N_INJECT = 3             # decoys injected per report for A2


def _norm(v: str) -> str:
    return v.strip().lower()


def _c2_threshold(dataset: str) -> float:
    """Conformal regex-confidence threshold fitted on the clean cached dataset."""
    with open(f"data/evaluation/calibration_predictions_{dataset}.json") as f:
        rows = json.load(f)
    preds = [(r["regex"], bool(r["correct"])) for r in rows
             if r.get("regex") is not None]
    return conformal_threshold(preds, C2_ALPHA, C2_DELTA)


def _extracted_values(text: str) -> list:
    """(value, confidence) for every IOC regex extracts from text."""
    return [(_norm(m.value), m.confidence)
            for m in extract_iocs_with_confidence(text, min_confidence=0.0)]


def _bootstrap_ratio(per_sample, seed=42, n_iter=1000, level=0.95):
    """Percentile CI for a pooled ratio, resampling (numerator, denominator)."""
    pairs = [p for p in per_sample if p[1] > 0]
    if not pairs:
        return (0.0, 0.0, 0.0)
    num = sum(n for n, _ in pairs)
    den = sum(d for _, d in pairs)
    point = num / den
    rng = random.Random(seed)
    draws = []
    for _ in range(n_iter):
        sample = [rng.choice(pairs) for _ in pairs]
        d = sum(d for _, d in sample)
        draws.append(sum(n for n, _ in sample) / d if d else 0.0)
    draws.sort()
    tail = (1.0 - level) / 2.0
    return (point, draws[int(tail * n_iter)],
            draws[min(n_iter - 1, int((1.0 - tail) * n_iter))])


def _injection_attack(samples, attack_class, n_inject, threshold):
    """Run A1/A2: measure injected-decoy survival before and after the C2 filter."""
    poisoned = build_adversarial_samples(samples, attack_class, n_inject)
    extracted_ps = []      # (injected decoys extracted, injected decoys total)
    applied_ps = []        # (injected decoys above C2 threshold, total)
    recall_ps = []         # (genuine IOCs still extracted, genuine total)
    for clean, atk in zip(samples, poisoned):
        ext = _extracted_values(atk["text"])
        ext_vals = {v for v, _ in ext}
        injected = [_norm(d["value"]) for d in atk["attack_meta"]["injected_iocs"]]

        def _hit(decoy):
            return [c for v, c in ext if v == decoy or decoy in v or v in decoy]

        extracted = sum(1 for d in injected if _hit(d))
        applied = sum(1 for d in injected
                      if any(c >= threshold for c in _hit(d)))
        extracted_ps.append((extracted, len(injected)))
        applied_ps.append((applied, len(injected)))

        expected = {_norm(e["value"]) for e in clean.get("expected_iocs", [])}
        found = sum(1 for e in expected
                    if any(e == v or e in v or v in e for v in ext_vals))
        recall_ps.append((found, len(expected)))

    return {
        "attack_class": attack_class,
        "n_injected_per_report": n_inject,
        "asr_no_mitigation": _bootstrap_ratio(extracted_ps, seed=1),
        "asr_with_c2": _bootstrap_ratio(applied_ps, seed=2),
        "genuine_recall": _bootstrap_ratio(recall_ps, seed=3),
    }


def _prompt_injection_attack():
    """Run A3: share of injection payloads neutralised by each defense."""
    rows = []
    for p in INJECTION_PAYLOADS:
        baseline = sanitize_for_prompt(p["text"], max_length=200)
        hardened = harden_verifier_context(p["text"])
        rows.append({
            "id": p["id"],
            "evasive": p["evasive"],
            "neutralized_baseline": is_neutralized(baseline),
            "neutralized_hardened": is_neutralized(hardened),
        })
    n = len(rows)
    return {
        "n_payloads": n,
        "asr_baseline_sanitizer": sum(1 for r in rows
                                      if not r["neutralized_baseline"]) / n,
        "asr_hardened_defense": sum(1 for r in rows
                                    if not r["neutralized_hardened"]) / n,
        "payloads": rows,
    }


def _fmt(ci):
    return f"{ci[0]:.1%} [{ci[1]:.1%}, {ci[2]:.1%}]"


def main() -> None:
    ap = argparse.ArgumentParser(description="Adversarial threat-model study.")
    ap.add_argument("--dataset", default="prism")
    args = ap.parse_args()

    samples = load_samples(args.dataset)
    threshold = _c2_threshold(args.dataset)
    print(f"=== Adversarial threat model — dataset: {args.dataset} "
          f"({len(samples)} reports) ===")
    print(f"  C2 conformal threshold (regex confidence, alpha={C2_ALPHA}, "
          f"delta={C2_DELTA}): {threshold:.4f}\n")

    a1 = _injection_attack(samples, "A1_flood", N_FLOOD, threshold)
    a2 = _injection_attack(samples, "A2_inject", N_INJECT, threshold)
    a3 = _prompt_injection_attack()

    print("  Report-borne false-IOC attacks — injected-decoy success rate:")
    print(f"  {'attack':<12s} {'no mitigation':>26s} {'+ C2 threshold':>26s}")
    print(f"  {'-'*12} {'-'*26} {'-'*26}")
    for r in (a1, a2):
        print(f"  {r['attack_class']:<12s} {_fmt(r['asr_no_mitigation']):>26s} "
              f"{_fmt(r['asr_with_c2']):>26s}")
    print(f"\n  Genuine-IOC recall under attack (should stay high — the attack")
    print(f"  adds false positives, it does not break extraction):")
    for r in (a1, a2):
        print(f"    {r['attack_class']:<12s} {_fmt(r['genuine_recall'])}")

    print(f"\n  A3 verifier prompt injection — payloads still carrying a")
    print(f"  recognisable injection directive ({a3['n_payloads']} payloads):")
    print(f"    sanitize_for_prompt (production) : "
          f"{a3['asr_baseline_sanitizer']:.0%}")
    print(f"    harden_verifier_context (new)    : "
          f"{a3['asr_hardened_defense']:.0%}")

    out = {
        "dataset": args.dataset,
        "n_reports": len(samples),
        "c2_threshold": round(threshold, 6),
        "c2_alpha": C2_ALPHA,
        "attacks": {"A1_flood": a1, "A2_inject": a2, "A3_prompt": a3},
    }
    out_path = f"data/evaluation/adversarial_study_{args.dataset}.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n💾 Saved to {out_path}")


if __name__ == "__main__":
    main()
