"""
Build a stratified human-verification sample for IOC labels.

When two teachers label the same reports they disagree (a 7B model and gpt-5.5
agree on only ~65% of IOCs). Neither label set is verified truth. This script
draws a stratified sample of IOCs — oversampling the disagreements, where the
signal is — and writes a CSV for a human analyst to adjudicate. The filled-in
CSV then yields a teacher-vs-human agreement number and lets a label set be
promoted from "silver" to "gold".

    python scripts/build_verification_sample.py \
        --baseline real_world_v2 --candidate real_world_v2_gpt55 \
        --output data/evaluation/verification_sample.csv --size 150

Each IOC is tagged by source:
  both           — in BOTH label sets (likely correct; sampled as a control)
  baseline_only  — only the baseline teacher found it
  candidate_only — only the candidate teacher found it

The analyst fills `is_true_ioc` (yes / no / unsure) and optional `notes`,
judging from the `context` snippet.
"""
import argparse
import csv
import os
import random
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from threat_intel_aggregator.evaluation.datasets import load_samples
from threat_intel_aggregator.feed_collection.ioc_deobfuscator import deobfuscate_text

CONTEXT_PAD = 110


def _key(e):
    return (e["value"].strip().lower(), e["type"].strip().lower())


def _context(text: str, value: str) -> str:
    """A one-line snippet of `text` around the first occurrence of `value`."""
    clean, _ = deobfuscate_text(text or "")
    hay = clean.lower()
    i = hay.find(value.strip().lower())
    if i < 0:
        return "(IOC not found in report text)"
    start, end = max(0, i - CONTEXT_PAD), i + len(value) + CONTEXT_PAD
    snippet = clean[start:end].replace("\n", " ").replace("\r", " ")
    snippet = " ".join(snippet.split())
    return ("…" if start else "") + snippet + ("…" if end < len(clean) else "")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a human IOC-verification CSV.")
    ap.add_argument("--baseline", default="real_world_v2", help="baseline dataset name/path")
    ap.add_argument("--candidate", default="real_world_v2_gpt55", help="candidate dataset name/path")
    ap.add_argument("--output", default="data/evaluation/verification_sample.csv")
    ap.add_argument("--size", type=int, default=150, help="target number of IOCs")
    ap.add_argument("--seed", type=int, default=42, help="sampling seed (reproducibility)")
    args = ap.parse_args()

    base = {s["id"]: s for s in load_samples(args.baseline)}
    cand = {s["id"]: s for s in load_samples(args.candidate)}

    # Classify every IOC across the shared reports.
    pools = {"both": [], "baseline_only": [], "candidate_only": []}
    for sid in base:
        if sid not in cand:
            continue
        text = cand[sid]["text"]
        b = {_key(e): e for e in base[sid]["expected_iocs"]}
        c = {_key(e): e for e in cand[sid]["expected_iocs"]}
        for k in set(b) | set(c):
            src = "both" if (k in b and k in c) else \
                  "baseline_only" if k in b else "candidate_only"
            e = b.get(k) or c.get(k)
            pools[src].append({
                "sample_id": sid,
                "ioc_value": e["value"],
                "ioc_type": e["type"],
                "label_source": src,
                "context": _context(text, e["value"]),
            })

    # Stratified draw: take all disagreements, fill the rest with agreements.
    rng = random.Random(args.seed)
    rows = []
    rows += pools["candidate_only"]                       # always all (small)
    base_quota = min(len(pools["baseline_only"]),
                     max(0, args.size - len(rows)) * 2 // 3)
    rows += rng.sample(pools["baseline_only"], base_quota)
    both_quota = min(len(pools["both"]), max(0, args.size - len(rows)))
    rows += rng.sample(pools["both"], both_quota)
    rng.shuffle(rows)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    fields = ["sample_id", "ioc_value", "ioc_type", "label_source",
              "context", "is_true_ioc", "notes"]
    with open(args.output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            r.setdefault("is_true_ioc", "")   # analyst fills: yes / no / unsure
            r.setdefault("notes", "")
            w.writerow(r)

    counts = {k: sum(r["label_source"] == k for r in rows) for k in pools}
    print(f"Wrote {len(rows)} IOCs to {args.output}")
    print(f"  pool sizes  — both={len(pools['both'])}  "
          f"baseline_only={len(pools['baseline_only'])}  "
          f"candidate_only={len(pools['candidate_only'])}")
    print(f"  sampled     — both={counts['both']}  "
          f"baseline_only={counts['baseline_only']}  "
          f"candidate_only={counts['candidate_only']}")
    print(f"\nFill the `is_true_ioc` column (yes / no / unsure) from `context`, "
          f"then re-run scoring against it.")


if __name__ == "__main__":
    main()
