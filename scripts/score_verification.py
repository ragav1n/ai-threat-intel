"""
Score a filled IOC-verification CSV against the two teachers' labels.

Given the analyst-filled `verification_sample.csv` (the `is_true_ioc` column
completed with yes/no/unsure), this computes — per teacher — how well its
labels match the human ground truth: precision, raw agreement, and Cohen's
kappa. It is the quantitative payoff of the human-verification step.

    python scripts/score_verification.py --csv data/evaluation/verification_sample.csv

Each row carries `label_source` ∈ {both, baseline_only, candidate_only}, which
implies what each teacher claimed:
  * baseline (qwen)  claims IOC for  both + baseline_only
  * candidate (gpt55) claims IOC for both + candidate_only
A row a teacher did NOT claim is its implicit "not an IOC" vote.
"""
import argparse
import csv
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

TEACHERS = {                       # teacher -> label_sources it claims as IOC
    "baseline (qwen2.5:7b)": {"both", "baseline_only"},
    "candidate (gpt-5.5)":   {"both", "candidate_only"},
}


def _cohen_kappa(a: list, b: list) -> float:
    """Cohen's kappa for two aligned lists of binary labels."""
    n = len(a)
    if n == 0:
        return float("nan")
    po = sum(x == y for x, y in zip(a, b)) / n
    pa1 = sum(a) / n
    pb1 = sum(b) / n
    pe = pa1 * pb1 + (1 - pa1) * (1 - pb1)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def main() -> None:
    ap = argparse.ArgumentParser(description="Score a filled IOC-verification CSV.")
    ap.add_argument("--csv", default="data/evaluation/verification_sample.csv")
    args = ap.parse_args()

    with open(args.csv, newline="") as f:
        rows = list(csv.DictReader(f))

    verdicts = {"yes": 1, "no": 0}
    filled = [r for r in rows if r.get("is_true_ioc", "").strip().lower() in verdicts]
    unsure = sum(r["is_true_ioc"].strip().lower() == "unsure" for r in rows)
    blank = len(rows) - len(filled) - unsure
    print(f"Rows: {len(rows)}  |  adjudicated yes/no: {len(filled)}  "
          f"|  unsure: {unsure}  |  blank: {blank}")
    if blank:
        print(f"⚠️  {blank} rows are not filled in — score is partial.")
    if not filled:
        print("Nothing adjudicated yet — aborting.")
        return

    # Per-stratum human verdict — the headline of the qwen-vs-gpt5.5 comparison.
    print("\nHuman verdict by label source (yes = genuine IOC):")
    for src in ("both", "baseline_only", "candidate_only"):
        sub = [r for r in filled if r["label_source"] == src]
        if sub:
            yes = sum(verdicts[r["is_true_ioc"].strip().lower()] for r in sub)
            print(f"  {src:15s}  {yes:3d}/{len(sub):3d} true IOC  ({yes/len(sub):.0%})")

    # Per-teacher precision + agreement vs the human.
    print()
    for teacher, claimed_sources in TEACHERS.items():
        human, teach = [], []
        for r in filled:
            human.append(verdicts[r["is_true_ioc"].strip().lower()])
            teach.append(1 if r["label_source"] in claimed_sources else 0)

        claimed = [(h, t) for h, t in zip(human, teach) if t == 1]
        precision = sum(h for h, _ in claimed) / len(claimed) if claimed else float("nan")
        agree = sum(h == t for h, t in zip(human, teach)) / len(human)
        kappa = _cohen_kappa(human, teach)
        print(f"{teacher}")
        print(f"  precision vs human : {precision:.3f}  "
              f"({sum(h for h,_ in claimed)}/{len(claimed)} claimed IOCs are genuine)")
        print(f"  agreement vs human : {agree:.3f}")
        print(f"  Cohen's kappa      : {kappa:.3f}")


if __name__ == "__main__":
    main()
