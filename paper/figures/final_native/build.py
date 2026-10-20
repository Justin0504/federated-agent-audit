"""Render final formal evidence only; never fill figures with development data."""
import argparse
import json
from pathlib import Path

LABELS = {
    "no_gate": "No gate", "gate_replan": "Gate + replan", "scope_replan": "Scope + replan",
    "receipt_replan": "Receipt + replan", "deny_egress": "Deny egress",
    "upstream_tool_filter": "Tool Filter (original)", "ipiguard": "IPIGuard",
    "upstream_tool_filter_resume": "Tool Filter + resume",
}
COLORS = ["#575757", "#B35D3A", "#B99537", "#3D776F", "#987363", "#607C96", "#865C76", "#344E6C"]


def validate(data):
    if data.get("complete") is not True or data.get("episodes") != 256:
        raise ValueError("Requires all256 formal episodes; no partial/development figures")
    if set(data["methods"]) != set(LABELS):
        raise ValueError("Unexpected methods")
    for method in data["methods"].values():
        for metric, n in (("all/utility", 32), ("clean/utility", 16), ("attacked/utility", 16),
                          ("attacked/attack_success", 16), ("attacked/joint", 16)):
            v = method["metrics"][metric]
            if v["planned"] != n or v["known"] + v["unknown"] != n:
                raise ValueError("Incorrect denominator")
            if v["unknown"]:
                raise ValueError("Unknown outcomes require an explicit display design; do not hide them")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path)
    parser.add_argument("--out", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    data = json.loads(args.summary.read_text())
    validate(data)
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "pdf.fonttype": 42, "svg.fonttype": "none"})
    args.out.mkdir(parents=True, exist_ok=True)
    panels = [("attacked/attack_success", "Native attack success (lower)"),
              ("clean/utility", "Clean task completion (higher)"),
              ("attacked/joint", "Attacked joint success (higher)")]
    fig, axes = plt.subplots(1, 3, figsize=(11.4, 4.3), sharey=True)
    for ax, (metric, title) in zip(axes, panels):
        for i, (arm, color) in enumerate(zip(LABELS, COLORS)):
            v = data["methods"][arm]["metrics"][metric]
            x = 100 * v["rate_known"]
            lo, hi = [100 * z for z in v["wilson95_known"]]
            ax.errorbar(x, i, xerr=[[max(0, x-lo)], [max(0, hi-x)]], fmt="o", color=color, capsize=3)
            ax.text(109, i, f'{v["successes"]}/{v["known"]}', va="center", ha="right", fontsize=8)
        ax.set_xlim(-5, 112)
        ax.set_xticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100%"])
        ax.set_title(title, fontsize=9, loc="left", pad=12)
        ax.spines[["top", "right", "left"]].set_visible(False)
        ax.grid(axis="x", color="#E4E0DB", linewidth=.5)
        ax.set_axisbelow(True)
        ax.tick_params(axis="y", length=0)
    axes[0].set_yticks(range(8), list(LABELS.values()))
    axes[0].tick_params(axis="y", labelleft=True)
    axes[0].invert_yaxis()
    fig.subplots_adjust(left=.20, right=.985, top=.88, bottom=.18, wspace=.25)
    fig.text(.20, .04, "Points: observed rates; bars: Wilson 95% intervals. Joint = task success and native attack failure.\nOne 14B model, one seed; native attack predicates do not cover all semantic privacy leakage.", fontsize=8)
    for ext in ("pdf", "svg", "png"):
        fig.savefig(args.out / ("formal_privacy_utility." + ext), dpi=220, facecolor="white")
    plt.close(fig)

    # The same dimensions, labels, and method colors make the two figures comparable.
    fig, axes = plt.subplots(1, 3, figsize=(11.4, 4.3), sharey=True)
    panels = [("model_calls", "Extra calls per task", 1),
              ("input_tokens", "Extra input tokens per task (k)", 1000),
              ("seconds", "Extra model-call time per task (s)", 1)]
    unknown_labels = []
    for ax, (field, title, scale) in zip(axes, panels):
        for i, (arm, color) in enumerate(zip(LABELS, COLORS)):
            v = data["methods"][arm]["paired_cost"][field]
            x, ci = v["mean_delta_vs_no_gate"], v["paired_bootstrap95"]
            if x is None:
                ax.text(.02, i, "Unknown", transform=ax.get_yaxis_transform(), va="center", fontsize=8)
            else:
                lo, hi = ci
                ax.errorbar(x / scale, i, xerr=[[max(0, x-lo) / scale], [max(0, hi-x) / scale]],
                            fmt="o", color=color, capsize=3)
            if v["paired_unknown"]:
                ax.annotate(f'n={v["paired_known"]}', (x / scale, i), xytext=(0, 9), textcoords="offset points", fontsize=7, ha="center")
                unknown_labels.append(f'{LABELS[arm]} / {field}: {v["paired_unknown"]} unknown pairs')
        ax.axvline(0, color="#AAA39A", linewidth=.8, linestyle="--")
        ax.set_title(title, fontsize=9, loc="left", pad=12)
        ax.spines[["top", "right", "left"]].set_visible(False)
        ax.grid(axis="x", color="#E4E0DB", linewidth=.5)
        ax.set_axisbelow(True)
        ax.tick_params(axis="y", length=0)
        ax.locator_params(axis="x", nbins=4)
    axes[0].set_yticks(range(8), list(LABELS.values()))
    axes[0].tick_params(axis="y", labelleft=True)
    axes[0].invert_yaxis()
    fig.subplots_adjust(left=.20, right=.985, top=.88, bottom=.18, wspace=.35)
    fig.text(.20, .04, "Difference versus no gate on the same task; bars: paired bootstrap 95% intervals.\nTiming is observational. Unknown pairs are excluded and enumerated in the accompanying audit file.", fontsize=8)
    (args.out / "cost_unknown_pairs.json").write_text(json.dumps(unknown_labels, indent=2))
    for ext in ("pdf", "svg", "png"):
        fig.savefig(args.out / ("formal_paired_cost." + ext), dpi=220, facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    main()
