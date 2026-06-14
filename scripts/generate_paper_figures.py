"""Generate the data-driven figures used in the IEEE Access paper.

Reads cached evaluation artifacts from ``data/evaluation/`` (produced by
``scripts/reproduce_all.py``) and writes PDF figures to
``paper/IEEE-Transactions-LaTeX2e-templates-and-instructions/figures/``.
Runs fully offline.
"""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "evaluation"
FIGDIR = ROOT / "paper" / "IEEE-Transactions-LaTeX2e-templates-and-instructions" / "figures"
FIGDIR.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 9,
    "axes.labelsize": 9,
    "axes.titlesize": 9,
    "legend.fontsize": 7.5,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "axes.grid": True,
    "grid.linewidth": 0.4,
    "grid.alpha": 0.5,
    "axes.linewidth": 0.6,
})


def load(name):
    with open(DATA / name) as f:
        return json.load(f)


def fig_obfuscation_collapse():
    d = load("obfuscation_baselines_prism.json")
    tiers = ["T0_clean", "T1_defang", "T2_encode", "T3_unicode", "T4_combined", "T5_adversarial"]
    tier_labels = ["T0", "T1", "T2", "T3", "T4", "T5"]
    series = {
        "ioc_finder": ("ioc-finder", "tab:orange", "o"),
        "iocextract": ("iocextract", "tab:green", "^"),
        "regex_only": ("regex only", "tab:gray", "s"),
        "our_pipeline": ("pipeline (regex+deobfusc.)", "tab:blue", "D"),
    }

    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    for key, (label, color, marker) in series.items():
        ys = [d["tiers"][t]["baselines"][key]["f1"] for t in tiers]
        ax.plot(tier_labels, ys, marker=marker, color=color, label=label,
                linewidth=1.3, markersize=4)

    ax.axvline(2.5, color="0.6", linestyle="--", linewidth=0.8)
    ax.text(2.52, 0.97, "obfuscation onset", fontsize=6.5, color="0.45",
            va="top", ha="left", style="italic")
    ax.set_xlabel("Obfuscation tier")
    ax.set_ylabel("F1 score (PRISM gold)")
    ax.set_ylim(-0.02, 1.0)
    ax.legend(loc="lower left", frameon=False)
    fig.tight_layout()
    fig.savefig(FIGDIR / "fig_obfuscation_collapse.pdf")
    plt.close(fig)


def fig_reliability():
    d = load("calibration_study_prism.json")
    fig, axes = plt.subplots(1, 2, figsize=(5.0, 2.4), sharey=True)

    for ax, key, title in zip(axes, ["Raw LLM", "Fused + Isotonic*"],
                               ["Raw LLM confidence", "Fused + isotonic (deployed)"]):
        bins = d["results"][key]["bins"]
        centers = [(i + 0.5) / 10 for i in range(10)]
        accs = [b["accuracy"] for b in bins]
        confs = [b["mean_confidence"] for b in bins]
        counts = [b["count"] for b in bins]
        width = 0.08
        bars_acc = [a if c > 0 else 0 for a, c in zip(accs, counts)]
        ax.bar(centers, bars_acc, width=width, color="tab:blue", alpha=0.7,
               label="empirical accuracy", edgecolor="none")
        ax.plot([0, 1], [0, 1], color="0.3", linestyle="--", linewidth=0.8,
                label="perfect calibration")
        nonzero = [c for c, n in zip(centers, counts) if n > 0]
        nonzero_conf = [cf for cf, n in zip(confs, counts) if n > 0]
        ax.scatter(nonzero, nonzero_conf, color="tab:red", marker="x", s=14,
                   label="mean confidence", zorder=3)
        ax.set_title(title + f"\nECE={d['results'][key]['ece']:.3f}", fontsize=8)
        ax.set_xlabel("Confidence bin")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)

    axes[0].set_ylabel("Accuracy")
    handles, labels = axes[1].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=3, frameon=False,
               bbox_to_anchor=(0.5, -0.02), fontsize=7)
    fig.tight_layout(rect=(0, 0.16, 1, 1))
    fig.savefig(FIGDIR / "fig_reliability.pdf", bbox_inches="tight")
    plt.close(fig)


def fig_conformal():
    d = load("conformal_study_prism.json")
    fig, ax = plt.subplots(figsize=(3.4, 2.6))

    colors = {"regex": "tab:blue", "fused": "tab:purple", "llm": "tab:red"}
    markers = {"regex": "o", "fused": "s", "llm": "^"}
    for source, sd in d["sources"].items():
        cov, risk, alphas = [], [], []
        for alpha_str, ad in sorted(sd["alphas"].items(), key=lambda kv: float(kv[0])):
            if ad["threshold"] is None:
                continue
            cov.append(ad["coverage"]["mean"])
            risk.append(ad["risk"]["mean"])
            alphas.append(float(alpha_str))
        if not cov:
            continue
        ax.plot(cov, risk, marker=markers[source], color=colors[source],
                label=f"{source} (AURC {sd['aurc']:.3f})", linewidth=1.2, markersize=4)
        for c, r, a in zip(cov, risk, alphas):
            ax.annotate(f"$\\alpha$={a:g}", (c, r), textcoords="offset points",
                         xytext=(4, 3), fontsize=6, color=colors[source])

    ax.axhline(0.10, color="0.5", linestyle=":", linewidth=0.8)
    ax.text(0.02, 0.105, "$\\alpha=0.10$ guarantee", fontsize=6.5, color="0.4")
    ax.set_xlabel("Coverage (fraction auto-applied)")
    ax.set_ylabel("Empirical FDR")
    ax.set_xlim(-0.02, 0.5)
    ax.set_ylim(-0.01, 0.16)
    ax.legend(loc="upper left", frameon=False)
    fig.tight_layout()
    fig.savefig(FIGDIR / "fig_conformal.pdf")
    plt.close(fig)


def fig_adversarial_asr():
    d = load("adversarial_study_prism.json")
    a1 = d["attacks"]["A1_flood"]
    a2 = d["attacks"]["A2_inject"]
    a3 = d["attacks"]["A3_prompt"]

    def mean(xs):
        return sum(xs) / len(xs)

    groups = ["A1 flood\n(report-borne)", "A2 inject\n(report-borne)", "A3 prompt\n(verifier IPI)"]
    before = [mean(a1["asr_no_mitigation"]), mean(a2["asr_no_mitigation"]), a3["asr_baseline_sanitizer"]]
    after = [mean(a1["asr_with_c2"]), mean(a2["asr_with_c2"]), a3["asr_hardened_defense"]]

    fig, ax = plt.subplots(figsize=(3.4, 2.6))
    x = range(len(groups))
    width = 0.35
    bars_before = ax.bar([i - width / 2 for i in x], before, width=width, color="tab:red",
                          label="no mitigation", alpha=0.8)
    bars_after = ax.bar([i + width / 2 for i in x], after, width=width, color="tab:blue",
                         label="with defense (C2 threshold /\nhardened verifier)", alpha=0.8)
    for b, v in zip(bars_before, before):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.03, f"{v:.2f}",
                ha="center", va="bottom", fontsize=6.5)
    for b, v in zip(bars_after, after):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.03, f"{v:.2f}",
                ha="center", va="bottom", fontsize=6.5)
    ax.set_xticks(list(x))
    ax.set_xticklabels(groups, fontsize=7)
    ax.set_ylabel("Attack success rate")
    ax.set_ylim(0, 1.08)
    fig.legend(loc="lower center", ncol=1, frameon=False, fontsize=7,
               bbox_to_anchor=(0.5, -0.06))
    fig.tight_layout(rect=(0, 0.13, 1, 1))
    fig.savefig(FIGDIR / "fig_adversarial_asr.pdf", bbox_inches="tight")
    plt.close(fig)


def fig_calibration_transfer():
    d = load("calibration_transfer.json")
    datasets = d["datasets"]
    matrix = [[d["transfer_matrix"][train][test] for test in datasets] for train in datasets]

    fig, ax = plt.subplots(figsize=(3.2, 2.8))
    im = ax.imshow(matrix, cmap="viridis", vmin=0, vmax=0.25)
    ax.set_xticks(range(len(datasets)))
    ax.set_yticks(range(len(datasets)))
    ax.set_xticklabels(datasets, rotation=40, ha="right", fontsize=7)
    ax.set_yticklabels(datasets, fontsize=7)
    ax.set_xlabel("Evaluated on")
    ax.set_ylabel("Calibrator fit on")
    for i in range(len(datasets)):
        for j in range(len(datasets)):
            val = matrix[i][j]
            color = "white" if val > 0.13 else "black"
            ax.text(j, i, f"{val:.3f}", ha="center", va="center", fontsize=6.5, color=color)
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("ECE", fontsize=7)
    cbar.ax.tick_params(labelsize=6.5)
    fig.tight_layout()
    fig.savefig(FIGDIR / "fig_calibration_transfer.pdf")
    plt.close(fig)


if __name__ == "__main__":
    fig_obfuscation_collapse()
    fig_reliability()
    fig_conformal()
    fig_adversarial_asr()
    fig_calibration_transfer()
    print(f"Wrote figures to {FIGDIR}")
