#!/usr/bin/env python3
"""Plot initialization and epoch costs of the 16-participant recovery workload.

The lower row removes the measured enrollment interval from epochs 1--3.
Initialization is bootstrap/initial issuance only, not a measured epoch-0
interval. No timing is synthesized, averaged, or pooled across lifecycles.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "benchmarks/results/main-lifecycle-20260925-032438/lifecycle"
DEST = ROOT / "figures/e2e-lifecycle-epochs"
COMMITTEES = ((4, 2, 1), (7, 3, 2), (13, 5, 4))
STAGES = (
    ("initial_generation_and_issuance", "Initial generation + issuance", "#0072B2", ""),
    ("new_enrollment", "New enrollment", "#E69F00", "//"),
    ("refresh", "Refresh", "#009E73", ""),
    ("other_epoch_work", "Other epoch work", "#999999", ".."),
)
RAW_METRICS = (
    "bootstrap_and_initial_issuance", "growth_issuance", "refresh",
    "epoch_with_growth",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract() -> tuple[list[dict], dict]:
    raw = SOURCE / "samples.jsonl"
    manifest_path = SOURCE / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    config = manifest["config"]
    assert config["committees"] == [list(c) for c in COMMITTEES]
    assert config["repeats"] == 1
    assert config["populations"] == [1024, 1024, 1280, 1280]
    assert config["thresholds"] == [128, 128, 160, 160]
    assert not config["fault_scenarios"] and not config["dealer_omission"]
    assert config["offline_participants"] == 16
    assert config["catchup_concurrency"] == 16
    assert config["participant_corruption_budget"] == 1
    assert config["outgoing_recipient_budget"] == 16
    samples = [(line, json.loads(text)) for line, text in
               enumerate(raw.read_text().splitlines(), 1)]
    provenance = {
        "samples": str(raw.relative_to(ROOT)), "samples_sha256": sha256(raw),
        "manifest": str(manifest_path.relative_to(ROOT)),
        "manifest_sha256": sha256(manifest_path), "config": config,
        "completions": [],
    }
    records = []
    for n, k, f in COMMITTEES:
        run = f"n{n}-baseline-trial000"
        completion_path = SOURCE / run / "completion.json"
        completion = json.loads(completion_path.read_text())
        assert completion["passed"] and completion["original_secret_reconstructed"]
        assert completion["epochs"] == 3 and not completion["faults"]
        provenance["completions"].append({
            "path": str(completion_path.relative_to(ROOT)),
            "sha256": sha256(completion_path),
        })

        def get(metric: str, epoch: int) -> tuple[int, dict]:
            selected = [(line, row) for line, row in samples
                        if row["run"] == run and row["epoch"] == epoch
                        and row["metric"] == metric]
            assert len(selected) == 1, (n, epoch, metric, len(selected))
            line, row = selected[0]
            assert row["status"] == "passed"
            assert row["evidence_kind"] == "measurement"
            assert row["scenario"] == "baseline" and row["trial"] == 0
            assert row["committee"] == [n, k] and row["protocol_fault_bound"] == f
            assert row["N"] == config["populations"][epoch]
            assert row["t"] == config["thresholds"][epoch]
            assert isinstance(row["duration_ns"], int) and row["duration_ns"] >= 0
            return line, row

        for epoch in range(4):
            off = 16 if epoch in (1, 2) else 0
            record = {
                "workload": "raised_sixteen", "n_D": n, "k_D": k, "f_D": f,
                "epoch": epoch, "epoch_label": "Init." if epoch == 0 else str(epoch),
                "source_t": config["thresholds"][max(0, epoch - 1)],
                "target_t": config["thresholds"][epoch],
                "N": config["populations"][epoch],
                "new_participants": 1024 if epoch == 0 else (256 if epoch == 2 else 0),
                "offline": off, "returning": 16 if epoch == 2 else 0,
                "trial": 0, "run": run,
                "source_file": provenance["samples"],
                "source_sha256": provenance["samples_sha256"],
            }
            values = {key: 0 for key, *_ in STAGES}
            lines = {metric: "" for metric in RAW_METRICS}
            if epoch == 0:
                line, initial = get("bootstrap_and_initial_issuance", 0)
                assert initial["data"]["participants"] == 1024
                interval_ns = initial["duration_ns"]
                interval_metric = "bootstrap_and_initial_issuance"
                values["initial_generation_and_issuance"] = interval_ns
                lines[interval_metric] = line
                without_enrollment_ns = ""
                raw_growth_ns = 0
            else:
                growth_line, growth = get("growth_issuance", epoch)
                refresh_line, refresh = get("refresh", epoch)
                interval_line, interval = get("epoch_with_growth", epoch)
                assert growth["data"]["new_participants"] == record["new_participants"]
                assert growth["data"]["source_t"] == record["source_t"]
                assert refresh["data"]["source_t"] == record["source_t"]
                assert not refresh["data"]["includes_growth_issuance"]
                assert refresh["data"]["offline"] == off
                assert interval["data"]["offline"] == off
                assert interval["data"]["includes_offline_catchup"] == (epoch == 2)
                _, liveness = get("liveness", epoch)
                assert liveness["data"]["offline"] == (list(range(1, 17)) if off else [])
                if epoch == 2:
                    _, group = get("offline_return_and_catchup", epoch)
                    assert group["data"]["participants"] == list(range(1, 17))
                    assert group["data"]["participant_count"] == 16
                    assert group["data"]["missed_epochs"] == 2
                    assert group["data"]["concurrency"] == 16
                interval_ns = interval["duration_ns"]
                interval_metric = "epoch_with_growth"
                raw_growth_ns = growth["duration_ns"]
                # A no-op timer is coordination, not enrollment of participants.
                values["new_enrollment"] = raw_growth_ns if record["new_participants"] else 0
                values["refresh"] = refresh["duration_ns"]
                values["other_epoch_work"] = (
                    interval_ns - values["new_enrollment"] - values["refresh"]
                )
                assert values["other_epoch_work"] >= 0
                without_enrollment_ns = interval_ns - values["new_enrollment"]
                assert without_enrollment_ns == values["refresh"] + values["other_epoch_work"]
                lines.update(growth_issuance=growth_line, refresh=refresh_line,
                             epoch_with_growth=interval_line)
            assert sum(values.values()) == interval_ns
            record.update(interval_metric=interval_metric, interval_ns=interval_ns,
                          interval_s=interval_ns / 1e9)
            record["raw_growth_issuance_ns"] = raw_growth_ns
            record["raw_growth_issuance_s"] = raw_growth_ns / 1e9
            for key, value in values.items():
                record[key + "_ns"] = value
                record[key + "_s"] = value / 1e9
            record["without_enrollment_ns"] = without_enrollment_ns
            record["without_enrollment_s"] = (
                without_enrollment_ns / 1e9 if isinstance(without_enrollment_ns, int) else ""
            )
            record.update({metric + "_source_line": line for metric, line in lines.items()})
            records.append(record)
    assert len(records) == 12
    return records, provenance


def plot(records: list[dict]) -> None:
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 7.5,
        "axes.labelsize": 7.5, "axes.titlesize": 8,
        "xtick.labelsize": 7, "ytick.labelsize": 7,
        "legend.fontsize": 7, "pdf.fonttype": 42, "ps.fonttype": 42,
        "hatch.linewidth": 0.35,
    })
    fig, axes = plt.subplots(2, 3, figsize=(4.8, 3.55), sharey="row")
    fig.subplots_adjust(left=0.115, right=0.99, top=0.785, bottom=0.17,
                        wspace=0.12, hspace=0.55)
    lookup = {(row["n_D"], row["epoch"]): row for row in records}
    for column, (n, k, f) in enumerate(COMMITTEES):
        for row_index, epochs in enumerate((range(4), range(1, 4))):
            ax = axes[row_index, column]
            data = [lookup[n, epoch] for epoch in epochs]
            x = list(epochs)
            bottom = [0.0] * len(data)
            stages = STAGES if row_index == 0 else STAGES[2:]
            for metric, _, color, hatch in stages:
                values = [r[metric + "_s"] for r in data]
                ax.bar(x, values, bottom=bottom, width=0.6, color=color,
                       edgecolor="#303030", linewidth=0.35, hatch=hatch, zorder=2)
                bottom = [a + b for a, b in zip(bottom, values)]
            for position, value in zip(x, bottom):
                ax.annotate(f"{value:.1f}", (position, value), xytext=(0, 3),
                            textcoords="offset points", ha="center", va="bottom",
                            fontsize=6.5)
            ax.set_xticks(x, ["Init." if e == 0 else str(e) for e in epochs])
            ax.set_xlim(min(x) - 0.5, max(x) + 0.5)
            ax.tick_params(axis="x", length=0, pad=3)
            ax.tick_params(axis="y", length=2, width=0.5)
            ax.set_axisbelow(True)
            ax.grid(axis="y", linewidth=0.35, color="#dddddd")
            ax.spines[["top", "right"]].set_visible(False)
            for spine in ("left", "bottom"):
                ax.spines[spine].set_linewidth(0.5)
            if row_index == 0:
                ax.set_ylim(0, 1300)
                ax.set_yticks([0, 400, 800, 1200])
                ax.set_title(rf"$(n_D,k_D,f_D)=({n},{k},{f})$", pad=5)
            else:
                ax.set_ylim(0, 100)
                ax.set_yticks([0, 25, 50, 75, 100])
        axes[0, 0].set_ylabel("Time (s)", labelpad=2)
        axes[1, 0].set_ylabel("Time (s)", labelpad=2)
    handles = [Patch(facecolor=color, edgecolor="#303030", linewidth=0.35,
                     hatch=hatch, label=label) for _, label, color, hatch in STAGES]
    fig.legend(handles=[handles[i] for i in (0, 2, 1, 3)], ncol=2,
               loc="upper center", bbox_to_anchor=(0.535, 1.005), frameon=False,
               handlelength=1.3, columnspacing=1.8, handletextpad=0.5,
               borderaxespad=0.4, labelspacing=0.5)
    fig.text(0.55, 0.877, "Initialization and epoch intervals", ha="center", va="center",
             fontsize=8)
    fig.text(0.55, 0.459, "Epoch intervals excluding enrollment", ha="center", va="center",
             fontsize=8)
    fig.text(0.55, 0.105, "Epoch", ha="center", va="center", fontsize=7)
    fig.text(0.55, 0.056, r"Epochs 0–3: $N=(1024,1024,1280,1280)$, $t=(128,128,160,160)$.",
             ha="center", va="center", fontsize=6.7)
    fig.text(0.55, 0.019, "16 participants miss updates 1 and 2; recover after epoch 2.",
             ha="center", va="center", fontsize=6.7)
    fig.savefig(DEST.with_suffix(".pdf"), metadata={
        "Title": "VESS initialization and epoch costs with sixteen returning participants",
        "Subject": "Three lifecycles; initialization and epoch intervals, with enrollment excluded in lower row",
        "Creator": "plot_paper_lifecycle.py", "CreationDate": None, "ModDate": None,
    })
    fig.savefig(DEST.with_suffix(".png"), dpi=300)
    plt.close(fig)


def main() -> None:
    records, provenance = extract()
    DEST.parent.mkdir(parents=True, exist_ok=True)
    with DEST.with_suffix(".csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    plot(records)
    metadata = {
        "title": "Initialization and epoch costs for sixteen returning participants",
        "script": str(Path(__file__).resolve().relative_to(ROOT)),
        "script_sha256": sha256(Path(__file__)),
        "workload": "raised_sixteen", "lifecycles": 3, "epochs": [0, 1, 2, 3],
        "observations_per_committee": 1, "aggregation": "none",
        "figure_size_inches": [4.8, 3.55],
        "axes": {"upper_y_seconds": [0, 1300], "lower_y_seconds": [0, 100]},
        "timing": {
            "unit": "seconds; exact nanoseconds also retained in CSV",
            "initialization": "bootstrap_and_initial_issuance; excludes initial reconstruction",
            "epochs_1_to_3": "epoch_with_growth; includes growth_issuance, refresh, and other epoch work",
            "other_epoch_work": "epoch_with_growth - new_enrollment - refresh, calculated in integer nanoseconds",
            "new_enrollment": "growth_issuance at epoch 2; zero at epochs 1 and 3, whose no-op growth timers are retained in other epoch work",
            "other_contents": "liveness classification, post-transition reconstruction, key rotation or catch-up when applicable, and coordination",
            "lower_row": "same epoch_with_growth observations minus new_enrollment; enrollment removed at epoch 2 only, not a new experiment",
            "zero_stage_values": "stage is absent from that plotted interval, not an independent zero-duration observation",
            "sum_scope": "bars are not the complete lifecycle total: initial and final reconstruction and between-interval overhead are not plotted",
        },
        "source": provenance,
        "artifacts": {suffix: sha256(DEST.with_suffix(suffix))
                      for suffix in (".csv", ".pdf", ".png")},
    }
    DEST.with_suffix(".meta.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Wrote {DEST.relative_to(ROOT)}.{{pdf,png,csv,meta.json}}")
    print("Validated 3 complete lifecycles, 12 upper intervals, and 9 enrollment-excluded intervals.")


if __name__ == "__main__":
    main()
