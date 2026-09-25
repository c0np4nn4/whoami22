#!/usr/bin/env python3
"""Visualize every Table-16 transition observation without rerunning benchmarks.

Each row of panels is one workload and each column is one committee. Five stage
intervals form a stacked bar; the measured refresh total is a separate black
tick and reconstruction is a neighboring hatched bar. Small reservation costs
are also printed in milliseconds. Refresh is never added to its own stages.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch


ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "figures" / "e2e-all-transitions"
WORKLOADS = (
    ("fixed_one", "Fixed threshold; 1 returning participant", "main-lifecycle-20260924-232853", 128, 1),
    ("raised_one", "Increased threshold; 1 returning participant", "main-lifecycle-20260925-020451", 160, 1),
    ("raised_sixteen", "Increased threshold; 16 returning participants", "main-lifecycle-20260925-032438", 160, 16),
)
COMMITTEES = ((4, 2, 1), (7, 3, 2), (13, 5, 4))
# Metric order is the original table's column order.
METRICS = (
    ("generation", "Generation", "#0072B2", "o", "-"),
    ("reservation_and_certificate", "Reservation", "#E69F00", "s", ":"),
    ("direct_delivery_stage", "Direct delivery", "#56B4E9", "^", "--"),
    ("archive_blob_publication", "Publication", "#CC79A7", "D", "-."),
    ("commit_and_apply", "Finalize/apply", "#009E73", "v", "--"),
    ("refresh", "Refresh (total)", "#000000", "X", "-"),
    ("reconstruct", "Reconstruction", "#D55E00", "P", ":"),
)

# Snapshot of the published table at plot preparation, retained so that the
# comparison remains possible after the figure replaces the table in main.tex.
TABLE_REFERENCE_LATEX = '\\begin{table}[!htbp]\n\\centering\n\\caption{Transition costs in seconds for all nine lifecycles. $e$ identifies the target epoch. Gen.: generation; reserve: reservation and certification; direct: direct delivery and staging; publish: archive and blob publication; apply: finalization and online application; recon.: secret reconstruction. Refresh is measured from generation through application, including coordination between stages; it excludes enrollment, liveness classification, key rotation, catch-up and reconstruction. Each entry is a single observation.}\n\\label{tab:lifecycle-current-transitions}\n\\small\n\\setlength{\\tabcolsep}{3pt}\n\\begin{tabular}{@{}rrrrrrrrr@{}}\n\\toprule\n$n_D$ & $e$ & \\shortstack{Gen.\\\\(s)} & \\shortstack{Reserve\\\\(s)} & \\shortstack{Direct\\\\(s)} & \\shortstack{Publish\\\\(s)} & \\shortstack{Apply\\\\(s)} & \\shortstack{Refresh\\\\(s)} & \\shortstack{Recon.\\\\(s)}\\\\\n\\midrule\n\\multicolumn{9}{@{}l}{\\emph{Fixed threshold, one returning participant}}\\\\[2pt]\n4 & 1 & 1.434 & 0.098 & 10.192 & 3.292 & 6.403 & 21.422 & 3.693\\\\\n4 & 2 & 1.564 & 0.114 & 12.776 & 0.527 & 8.211 & 23.196 & 3.931\\\\\n4 & 3 & 1.571 & 0.119 & 12.654 & 0.496 & 7.975 & 22.818 & 3.757\\\\\n\\addlinespace[2pt]\n7 & 1 & 4.162 & 0.176 & 12.698 & 2.674 & 7.505 & 27.219 & 4.057\\\\\n7 & 2 & 4.397 & 0.161 & 15.849 & 1.058 & 9.603 & 31.080 & 3.987\\\\\n7 & 3 & 4.389 & 0.164 & 15.992 & 0.996 & 9.291 & 30.836 & 3.951\\\\\n\\addlinespace[2pt]\n13 & 1 & 24.097 & 0.257 & 18.797 & 4.353 & 11.159 & 58.677 & 4.271\\\\\n13 & 2 & 24.174 & 0.330 & 23.575 & 2.796 & 13.548 & 64.428 & 4.236\\\\\n13 & 3 & 25.014 & 0.285 & 23.758 & 2.628 & 13.167 & 64.859 & 4.255\\\\\n\\addlinespace[4pt]\n\\multicolumn{9}{@{}l}{\\emph{Increased threshold, one returning participant}}\\\\[2pt]\n4 & 1 & 1.468 & 0.109 & 9.904 & 3.227 & 6.445 & 21.156 & 3.843\\\\\n4 & 2 & 1.811 & 0.119 & 14.243 & 0.564 & 8.895 & 25.636 & 5.862\\\\\n4 & 3 & 1.865 & 0.131 & 14.919 & 0.585 & 9.173 & 26.677 & 5.841\\\\\n\\addlinespace[2pt]\n7 & 1 & 4.158 & 0.172 & 12.780 & 2.639 & 7.505 & 27.264 & 3.791\\\\\n7 & 2 & 5.313 & 0.180 & 18.537 & 1.160 & 10.266 & 35.461 & 5.864\\\\\n7 & 3 & 5.405 & 0.195 & 19.084 & 1.248 & 10.996 & 36.933 & 5.986\\\\\n\\addlinespace[2pt]\n13 & 1 & 22.824 & 0.273 & 18.798 & 4.330 & 11.458 & 57.689 & 4.207\\\\\n13 & 2 & 29.620 & 0.297 & 27.186 & 3.137 & 14.936 & 75.182 & 6.341\\\\\n13 & 3 & 29.923 & 0.308 & 29.408 & 3.387 & 15.647 & 78.681 & 6.415\\\\\n\\addlinespace[4pt]\n\\multicolumn{9}{@{}l}{\\emph{Increased threshold, $16$ returning participants}}\\\\[2pt]\n4 & 1 & 1.450 & 0.097 & 9.764 & 3.563 & 6.350 & 21.230 & 3.817\\\\\n4 & 2 & 1.832 & 0.113 & 14.285 & 0.901 & 8.699 & 25.836 & 5.866\\\\\n4 & 3 & 1.865 & 0.125 & 14.806 & 0.582 & 8.912 & 26.293 & 5.801\\\\\n\\addlinespace[2pt]\n7 & 1 & 4.172 & 0.140 & 12.379 & 3.344 & 7.446 & 27.484 & 3.923\\\\\n7 & 2 & 5.289 & 0.191 & 18.283 & 1.852 & 10.178 & 35.799 & 6.227\\\\\n7 & 3 & 5.272 & 0.162 & 19.047 & 1.211 & 10.611 & 36.311 & 5.853\\\\\n\\addlinespace[2pt]\n13 & 1 & 23.236 & 0.268 & 18.554 & 5.536 & 11.658 & 59.259 & 4.200\\\\\n13 & 2 & 30.094 & 0.328 & 27.527 & 4.383 & 15.230 & 77.570 & 6.637\\\\\n13 & 3 & 30.886 & 0.347 & 29.126 & 3.361 & 15.827 & 79.554 & 6.471\\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}'


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def table_reference() -> list[list[str]]:
    rows = []
    for line in TABLE_REFERENCE_LATEX.splitlines():
        if re.match(r"^\d+\s*&", line):
            cells = line.removesuffix(r"\\").replace("{,}", "").split("&")
            rows.append([cell.strip() for cell in cells])
    assert len(rows) == 27 and all(len(row) == 9 for row in rows)
    assert r"\label{tab:lifecycle-current-transitions}" in TABLE_REFERENCE_LATEX
    return rows


def extract() -> tuple[list[dict], list[dict]]:
    observations = []
    sources = []
    for workload, _, directory, raised_t, offline in WORKLOADS:
        lifecycle = ROOT / "benchmarks/results" / directory / "lifecycle"
        raw = lifecycle / "samples.jsonl"
        manifest_path = lifecycle / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        config = manifest["config"]
        assert config["repeats"] == 1
        assert config["populations"] == [1024, 1024, 1280, 1280]
        assert config["thresholds"] == [128, 128, raised_t, raised_t]
        assert not config["fault_scenarios"] and not config["dealer_omission"]
        assert config.get("offline_participants", 1) == offline
        assert all(list(c) in config["committees"] for c in COMMITTEES)
        samples = [(line, json.loads(text)) for line, text in
                   enumerate(raw.read_text().splitlines(), 1)]
        source = {
            "workload": workload, "samples": str(raw.relative_to(ROOT)),
            "samples_sha256": sha256(raw),
            "manifest": str(manifest_path.relative_to(ROOT)),
            "manifest_sha256": sha256(manifest_path), "config": config,
            "completions": [],
        }
        for n, k, f in COMMITTEES:
            run = f"n{n}-baseline-trial000"
            completion_path = lifecycle / run / "completion.json"
            completion = json.loads(completion_path.read_text())
            assert completion["passed"] and completion["original_secret_reconstructed"]
            assert completion["epochs"] == 3 and not completion["faults"]
            source["completions"].append({
                "path": str(completion_path.relative_to(ROOT)),
                "sha256": sha256(completion_path),
            })
            for epoch in (1, 2, 3):
                record = {
                    "workload": workload, "n_D": n, "k_D": k, "f_D": f,
                    "epoch": epoch,
                    "source_t": config["thresholds"][epoch - 1],
                    "target_t": config["thresholds"][epoch],
                    "N": config["populations"][epoch],
                    "offline": offline if epoch < 3 else 0,
                    "trial": 0, "run": run,
                    "source_file": source["samples"],
                    "source_sha256": source["samples_sha256"],
                }
                for metric, *_ in METRICS:
                    selected = [(line, row) for line, row in samples
                                if row["run"] == run and row["epoch"] == epoch
                                and row["metric"] == metric]
                    assert len(selected) == 1, (directory, n, epoch, metric, len(selected))
                    line, row = selected[0]
                    assert row["status"] == "passed"
                    assert row["evidence_kind"] == "measurement"
                    assert row["scenario"] == "baseline" and row["trial"] == 0
                    assert row["committee"] == [n, k] and row["protocol_fault_bound"] == f
                    assert row["N"] == record["N"] and row["t"] == record["target_t"]
                    assert isinstance(row["duration_ns"], int) and row["duration_ns"] > 0
                    if metric == "reconstruct":
                        assert row["data"]["epoch"] == epoch
                        assert row["data"]["threshold"] == record["target_t"]
                        assert row["data"]["secret_matches_owner"]
                    else:
                        assert row["data"]["nonce"] == epoch
                    if metric == "refresh":
                        assert row["data"]["source_t"] == record["source_t"]
                        assert row["data"]["offline"] == record["offline"]
                        assert not row["data"]["includes_growth_issuance"]
                    record[metric + "_ns"] = row["duration_ns"]
                    record[metric + "_s"] = row["duration_ns"] / 1e9
                    record[metric + "_source_line"] = line
                    assert 0 < record[metric + "_s"] < 90
                stage_sum = sum(record[metric + "_ns"] for metric, *_ in METRICS[:5])
                record["coordination_residual_ns"] = record["refresh_ns"] - stage_sum
                assert 0 <= record["coordination_residual_ns"] < 15_000_000
                observations.append(record)
        sources.append(source)
    assert len(observations) == 27
    reference = table_reference()
    for observation, expected in zip(observations, reference):
        actual = [str(observation["n_D"]), str(observation["epoch"])]
        actual += [f"{observation[metric + '_s']:.3f}" for metric, *_ in METRICS]
        assert actual == expected, (actual, expected)
    return observations, sources


def plot(observations: list[dict]) -> None:
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 7.5,
        "axes.labelsize": 7.5, "axes.titlesize": 8,
        "xtick.labelsize": 7, "ytick.labelsize": 7,
        "legend.fontsize": 6.8, "pdf.fonttype": 42, "ps.fonttype": 42,
        "hatch.linewidth": 0.35,
    })
    fig, axes = plt.subplots(3, 3, figsize=(4.8, 5.2), sharey=True, sharex=True)
    fig.subplots_adjust(left=0.12, right=0.99, top=0.81, bottom=0.12,
                        wspace=0.13, hspace=0.62)
    lookup = {(row["workload"], row["n_D"], row["epoch"]): row for row in observations}
    hatches = {"reservation_and_certificate": "//", "commit_and_apply": "\\\\"}
    for row_index, (workload, _, *_rest) in enumerate(WORKLOADS):
        for column, (n, k, f) in enumerate(COMMITTEES):
            ax = axes[row_index, column]
            data = [lookup[workload, n, epoch] for epoch in (1, 2, 3)]
            main_x = [epoch - 0.14 for epoch in (1, 2, 3)]
            bottom = [0.0] * 3
            for metric, _, color, *_ in METRICS[:5]:
                values = [row[metric + "_s"] for row in data]
                ax.bar(main_x, values, bottom=bottom, width=0.48, color=color,
                       hatch=hatches.get(metric, ""), edgecolor="#303030",
                       linewidth=0.3, zorder=2)
                bottom = [a + b for a, b in zip(bottom, values)]
            ax.plot(main_x, [row["refresh_s"] for row in data], linestyle="none",
                    marker="_", color="black", markersize=6,
                    markeredgewidth=1.05, zorder=5)
            ax.bar([epoch + 0.29 for epoch in (1, 2, 3)],
                   [row["reconstruct_s"] for row in data], width=0.2,
                   facecolor="#f0f0f0", edgecolor="#505050", hatch="////",
                   linewidth=0.4, zorder=2)
            reservation = " / ".join(f"{row['reservation_and_certificate_s'] * 1000:.0f}"
                                     for row in data)
            ax.text(0.5, 1.045, f"Reserve (ms): {reservation}", transform=ax.transAxes,
                    ha="center", va="bottom", fontsize=6.2)
            ax.set_ylim(0, 90)
            ax.set_yticks([0, 30, 60, 90])
            ax.set_xticks([1, 2, 3])
            ax.set_xlim(0.5, 3.5)
            ax.tick_params(axis="x", length=2, width=0.5, pad=3, labelbottom=True)
            ax.tick_params(axis="y", length=2, width=0.5, pad=3)
            ax.set_axisbelow(True)
            ax.grid(axis="y", linewidth=0.35, color="#dddddd")
            ax.spines[["top", "right"]].set_visible(False)
            for spine in ("left", "bottom"):
                ax.spines[spine].set_linewidth(0.5)
            if row_index == 0:
                ax.set_title(rf"$(n_D,k_D,f_D)=({n},{k},{f})$", pad=18)
        axes[row_index, 0].set_ylabel("Time (s)", labelpad=3)
    handles = [Patch(facecolor=color, edgecolor="#303030", linewidth=0.3,
                     hatch=hatches.get(metric, ""), label=label)
               for metric, label, color, *_ in METRICS[:5]]
    handles += [Line2D([], [], color="black", marker="_", linestyle="none",
                       markersize=6, markeredgewidth=1.05, label="Refresh (total)"),
                Patch(facecolor="#f0f0f0", edgecolor="#505050", linewidth=0.4,
                      hatch="////", label="Reconstruction")]
    fig.legend(handles=[handles[i] for i in (0, 4, 1, 5, 2, 6, 3)], ncol=4,
               loc="upper center", bbox_to_anchor=(0.53, 1.005), frameon=False,
               handlelength=1.65, columnspacing=1.05, handletextpad=0.4,
               borderaxespad=0.6, labelspacing=0.75)
    for (_, title, *_), y in zip(WORKLOADS, (0.901, 0.595, 0.323)):
        fig.text(0.555, y, title, ha="center", va="center", fontsize=8)
    fig.text(0.555, 0.055, "Target epoch", ha="center", va="center", fontsize=8)
    fig.savefig(DEST.with_suffix(".pdf"), metadata={
        "Title": "All VESS lifecycle transition observations",
        "Subject": "27 transitions and seven timing metrics, one independent lifecycle per workload and committee",
        "Creator": "plot_paper_transitions.py", "CreationDate": None, "ModDate": None,
    })
    fig.savefig(DEST.with_suffix(".png"), dpi=300)
    plt.close(fig)


def main() -> None:
    observations, sources = extract()
    DEST.parent.mkdir(parents=True, exist_ok=True)
    with DEST.with_suffix(".csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(observations[0]))
        writer.writeheader()
        writer.writerows(observations)
    plot(observations)
    metadata = {
        "title": "All transition-stage observations",
        "script": str(Path(__file__).resolve().relative_to(ROOT)),
        "script_sha256": sha256(Path(__file__)),
        "lifecycles": 9, "transitions": 27, "timing_observations": 189,
        "observations_per_workload_and_committee": 1,
        "aggregation": "none; epochs belong to the same lifecycle, not independent repetitions",
        "figure_size_inches": [4.8, 5.2],
        "axis": {"x": "target epoch 1, 2, 3", "y": "seconds, linear", "limits": [0, 90]},
        "plot_encoding": {
            "main_bar": "five measured stages stacked without adding refresh a second time",
            "black_tick": "independently measured refresh interval",
            "neighboring_gray_hatched_bar": "subsequent reconstruction, outside refresh",
            "reservation_annotation": "same reservation measurements repeated in milliseconds above each panel, ordered epochs 1 / 2 / 3",
            "reservation_annotation_rounding": "nearest millisecond, matching the three-decimal-second precision of the source table",
        },
        "timing": {
            "metrics": [metric for metric, *_ in METRICS],
            "unit": "seconds; exact nanoseconds retained in CSV",
            "refresh": "independent timing from generation through online application, containing the first five stage intervals",
            "reconstruction": "subsequent secret reconstruction; outside refresh",
            "excluded_from_refresh": ["enrollment", "liveness classification", "key rotation", "catch-up", "reconstruction"],
            "sum_warning": "refresh is a nested total and is not additive with its constituent stages",
            "maximum_stack_to_refresh_residual_ns": max(
                row["coordination_residual_ns"] for row in observations),
        },
        "table_reference": {
            "label": "tab:lifecycle-current-transitions",
            "latex": TABLE_REFERENCE_LATEX,
            "sha256": hashlib.sha256(TABLE_REFERENCE_LATEX.encode()).hexdigest(),
            "comparison": "all 27 rows and 189 durations exactly match original table after rounding to 3 decimal places",
        },
        "sources": sources,
        "artifacts": {suffix: sha256(DEST.with_suffix(suffix))
                      for suffix in (".csv", ".pdf", ".png")},
    }
    DEST.with_suffix(".meta.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Wrote {DEST.relative_to(ROOT)}.{{pdf,png,csv,meta.json}}")
    print("Validated 9 completed lifecycles, 27 transitions, 189 timings, and all original Table-16 cells.")


if __name__ == "__main__":
    main()
