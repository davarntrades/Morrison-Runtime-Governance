"""
Renders the architecture diagram: Agent → Governance Layer → Tool Runtime,
with the seven enforcement layers. PNG + SVG.

Run:
    python3 artifacts/visualizations/architecture.py
"""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = Path(__file__).resolve().parent

LAYERS = [
    ("A_safe", "single-step Ω pattern match"),
    ("V2",     "trajectory drift + source→sink taint"),
    ("V3",     "forward reachability projection"),
    ("V4",     "state-space admissibility"),
    ("V4+",    "feasibility — refuse to guess"),
    ("V5",     "environment-wide stability (ℰ)"),
    ("V5+",    "hard adversarial test harness"),
]


def box(ax, x, y, w, h, text, fc, ec="#1f2937", fs=11, weight="bold"):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
        linewidth=1.6, edgecolor=ec, facecolor=fc))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, fontweight=weight, color="#111827")


def arrow(ax, p1, p2, color="#374151", style="-|>", lw=2.0):
    ax.add_patch(FancyArrowPatch(
        p1, p2, arrowstyle=style, mutation_scale=18,
        linewidth=lw, color=color, shrinkA=2, shrinkB=2))


def main():
    fig, ax = plt.subplots(figsize=(12, 7.2))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 7.2)
    ax.axis("off")

    # Agent
    box(ax, 0.3, 3.0, 2.1, 1.4, "AGENT\n(LLM / planner)", "#dbeafe", fs=11)

    # Governance container
    ax.add_patch(FancyBboxPatch(
        (3.5, 0.5), 5.0, 6.2, boxstyle="round,pad=0.03,rounding_size=0.08",
        linewidth=2.2, edgecolor="#1e3a8a", facecolor="#f8fafc"))
    ax.text(6.0, 6.35, "GOVERNANCE LAYER", ha="center", va="center",
            fontsize=13, fontweight="bold", color="#1e3a8a")

    palette = ["#fee2e2", "#ffedd5", "#ede9fe", "#dbeafe",
               "#cffafe", "#dcfce7", "#fce7f3"]
    y = 5.55
    for (name, desc), fc in zip(LAYERS, palette):
        box(ax, 3.8, y, 4.4, 0.62, "", fc, fs=10)
        ax.text(4.05, y + 0.31, name, ha="left", va="center",
                fontsize=11, fontweight="bold", color="#111827")
        ax.text(5.05, y + 0.31, desc, ha="left", va="center",
                fontsize=9.5, color="#374151")
        y -= 0.74

    # Tool runtime
    box(ax, 9.6, 3.0, 2.1, 1.4,
        "TOOL RUNTIME\n(shell / API /\nfs / browser)", "#e5e7eb", fs=10)

    # Flows
    arrow(ax, (2.4, 3.7), (3.5, 3.7))
    ax.text(2.95, 3.95, "proposed\ntool call", ha="center", va="bottom",
            fontsize=8.5, color="#374151")

    arrow(ax, (8.5, 3.7), (9.6, 3.7), color="#16a34a", lw=2.4)
    ax.text(9.05, 3.95, "PERMIT", ha="center", va="bottom",
            fontsize=9, fontweight="bold", color="#16a34a")

    arrow(ax, (6.0, 0.5), (6.0, 0.05), color="#dc2626", lw=2.4)
    ax.text(6.2, 0.22, "BLOCK — denied, never reaches the runtime",
            ha="left", va="center", fontsize=9, fontweight="bold",
            color="#dc2626")

    ax.text(6.0, 7.0,
            "Invariant:   ∀ E ∈ ℰ,   ℛ_E(t) ∩ Ω = ∅",
            ha="center", va="center", fontsize=11, style="italic",
            color="#1e3a8a")

    fig.suptitle("Morrison Runtime Governance — pre-execution control plane",
                 fontsize=14, fontweight="bold", y=0.995)
    plt.tight_layout()
    fig.savefig(OUT / "architecture.png", dpi=160, bbox_inches="tight")
    fig.savefig(OUT / "architecture.svg", bbox_inches="tight")
    plt.close(fig)
    print("wrote architecture.png + architecture.svg")


if __name__ == "__main__":
    main()
