#!/usr/bin/env python3
"""Verify normal lifecycles using process, protocol, sample and receipt evidence."""
import json
import sys
from collections import Counter
from pathlib import Path


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def json_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


NORMAL_METRICS = {
    "deployment_and_process_setup", "bootstrap_and_initial_issuance", "initial_secret_check",
    "growth_issuance", "liveness", "generation", "reservation_and_certificate",
    "direct_delivery_stage", "archive_blob_publication", "commit_and_apply", "refresh",
    "authentication_key_rotation", "offline_catchup", "participant_catchup", "offline_return_and_catchup",
    "reconstruct", "epoch_with_growth", "final_reconstruct", "lifecycle",
}


def catchup_plan(config):
    """Legacy runs omit these fields and recover participant 1 only."""
    count = config.get("offline_participants", 1)
    concurrency = config.get("catchup_concurrency", 16)
    delta = config.get("participant_corruption_budget", 1)
    outgoing = config.get("outgoing_recipient_budget", 2)
    require(all(type(value) is int for value in (count, concurrency, delta, outgoing)), "integer catch-up and release policy parameters")
    require(1 <= count <= config["populations"][0] and concurrency > 0 and delta >= 0 and outgoing >= count, "catch-up population, concurrency and outgoing recipient budget")
    return list(range(1, count + 1)), concurrency, delta, outgoing


def verify_processes(trial, events, dealers, population, offline_participants):
    expected_roles = {i: "dealer" for i in range(1, dealers + 1)}
    expected_roles.update({8001: "owner", 9001: "archive", 9002: "archive"})
    expected_roles.update({1000 + i: "participant" for i in range(1, population + 1)})
    offline_nodes = {1000 + participant for participant in offline_participants}
    active, starts, stops, instances = {}, Counter(), [], []
    for event in json_lines(trial / "nodes/process_events.jsonl"):
        node = event["id"]
        require(event["role"] == expected_roles.get(node), "unexpected process identity")
        require(isinstance(event["pid"], int) and event["pid"] > 0, "missing process PID")
        if event["action"] == "start":
            require(node not in active, f"process {node}: duplicate start")
            active[node] = event["pid"]
            starts[node] += 1
            instances.append((node, event["role"], event["pid"]))
        elif event["action"] == "stop":
            require(active.pop(node, None) == event["pid"], f"process {node}: unmatched stop")
            require(node in offline_nodes, "dealer/archive or unplanned participant stop")
            stops.append(node)
        else:
            raise ValueError(f"unknown process action: {event['action']}")
    require(Counter(stops) == Counter(offline_nodes), "each planned offline participant must stop exactly once")
    require(starts == Counter({node: 2 if node in offline_nodes else 1 for node in expected_roles}), "unexpected process start/restart counts")
    require(set(active) == set(expected_roles), "all processes must be active at completion")
    node_starts = [(e["node"], e["role"], e["pid"]) for e in events if e["kind"] == "process_started"]
    require(Counter(node_starts) == Counter(instances), "runner/node process evidence mismatch")
    return len(instances)


def verify_catchup(by_metric, events, participants, concurrency, n, k, thresholds, populations, explicit_plan):
    expected = Counter((recipient, epoch) for recipient in participants for epoch in (1, 2))
    catchup = by_metric.get("offline_catchup", [])
    def recipient(sample):
        require(not explicit_plan or "recipient" in sample["data"], "catch-up measurement must identify its recipient")
        return sample["data"].get("recipient", 1)
    require(Counter((recipient(s), s["epoch"]) for s in catchup) == expected, "one recovery per planned participant and missed epoch required")
    require(all(s["t"] == thresholds[s["epoch"]] and s["N"] == populations[2] for s in catchup), "catch-up historical threshold and population at return")
    require(all(s["data"]["dealers_running"] == n and s["data"]["archive_replicas_running"] == 2 and s["data"]["localized"] == 0 and s["data"]["vector_fetches"] == 0 and s["data"]["records_read"] == k and s["data"]["nonce"] == s["epoch"] for s in catchup), "normal archive recovery conditions")
    caught_up = [e for e in events if e["kind"] == "catchup_applied"]
    require(Counter((e["node"] - 1000, e["data"]["nonce"]) for e in caught_up) == expected, "executed catch-up applications for every recipient and missed epoch")
    require(all(e["role"] == "participant" and e["data"]["localized"] == 0 and e["data"]["vector_fetches"] == 0 and e["data"]["records"] == k for e in caught_up), "normal participant catch-up evidence")
    for participant in participants:
        rows = [e for e in caught_up if e["node"] == 1000 + participant]
        require([e["data"]["nonce"] for e in rows] == [1, 2], "each returning participant applies missed epochs in order")
        require(rows[0]["pid"] == rows[1]["pid"] and rows[0]["local_ns"] < rows[1]["local_ns"], "sequential recovery in the same participant process")
        for event in rows:
            targets = {e["data"]["target"] for e in events if e["kind"] == "commit_applied" and e["data"]["epoch"] == event["data"]["nonce"]}
            require(targets == {event["data"]["target"]}, "catch-up must install the canonical committed target")
    totals = by_metric.get("participant_catchup", [])
    if explicit_plan or totals:
        require(Counter(s["data"]["recipient"] for s in totals) == Counter(participants), "one total catch-up measurement per returning participant")
        require(all(s["epoch"] == 2 and s["t"] == thresholds[2] and s["N"] == populations[2] and s["data"]["missed_epochs"] == 2 and s["data"]["completed_epochs"] == [1, 2] and s["data"]["target_epoch"] == 2 and s["data"]["records_read"] == 2 * k for s in totals), "each participant recovered both transitions to epoch 2")
    group = by_metric["offline_return_and_catchup"][0]
    require(group["epoch"] == 2 and group["t"] == thresholds[2] and group["N"] == populations[2] and group["data"]["missed_epochs"] == 2, "aggregate catch-up target and missed epochs")
    if explicit_plan:
        require(group["data"]["participant_count"] == len(participants) and group["data"]["participants"] == participants and group["data"]["concurrency"] == min(concurrency, len(participants)), "aggregate catch-up participant identities and worker limit")


def verify_trial(trial, measured, committee, thresholds, populations, config=None):
    n, k, f = committee
    epochs = len(thresholds)
    transitions = epochs - 1
    completion = read(trial / "completion.json")
    require(completion["passed"] is True and completion["original_secret_reconstructed"] is True, f"{trial.name}: incomplete")
    require(completion["faults"] is False and completion["epochs"] == transitions, "normal trial completion scope")
    events = [e for path in trial.glob("nodes/*/events.jsonl") for e in json_lines(path)]
    require(events and all(e["run"] == trial.name for e in events), "missing/mixed node events")
    require(not any(e["kind"] in {"fault_injected", "fault_configured", "archive_records_hidden", "reconstruction_share_rejected"} for e in events), "fault injection, hidden records or rejected reconstruction in normal run")
    config = config if config is not None else {"populations": populations}
    offline_participants, concurrency, delta, outgoing = catchup_plan(config)
    explicit_plan = "offline_participants" in config
    starts = verify_processes(trial, events, n, populations[-1], offline_participants)
    node_configs = [read(path) for path in trial.glob("nodes/*/node.json")]
    require(node_configs and all([c["n"], c["k"], c["f"]] == [n, k, f] for c in node_configs), "configured committee parameters delivered to every node")
    require(all(c.get("participant_corruption_budget", 1) == delta and c.get("outgoing_recipient_budget", 2) == outgoing for c in node_configs), "release policy delivered to every node")
    policy_configurations = list(trial.glob("chain/*-configure-release-policy.json"))
    if explicit_plan or policy_configurations:
        require(len(policy_configurations) == 1, "one on-chain release policy configuration required")
        policy = read(policy_configurations[0])
        data = bytes.fromhex(policy["transaction"]["data"].removeprefix("0x"))
        require(len(data) == 68 and data[:4].hex() == "32ef72d2", "configureReleasePolicy calldata")
        require([int.from_bytes(data[4 + 32*i:36 + 32*i], "big") for i in range(2)] == [delta, outgoing] and int(policy["receipt"]["status"], 16) == 1, "configured release policy accepted on chain")
    configurations = list(trial.glob("chain/*-configure-generation-broadcast.json"))
    require(len(configurations) == 1, "one on-chain committee configuration required")
    configuration = read(configurations[0])
    calldata = bytes.fromhex(configuration["transaction"]["data"].removeprefix("0x"))
    require(len(calldata) == 132 and calldata[:4].hex() == "733535b2", "configureGeneration calldata")
    configured = [int.from_bytes(calldata[4 + 32*i:36 + 32*i], "big") for i in range(3)]
    require(configured == [n, k, f] and int(configuration["receipt"]["status"], 16) == 1, "explicit committee parameters accepted on chain")
    require(measured and all(s["scenario"] == "baseline" and s["status"] == "passed" for s in measured), "non-normal/failed measurement")
    require(all(s["schema_version"] == 2 and s["committee"] == [n, k] and s["protocol_fault_bound"] == f for s in measured), "measurement committee/protocol fault bound mismatch")
    require(all(s["metric"] in NORMAL_METRICS for s in measured), "fault or unknown measurement in normal run")
    by_metric = {}
    for sample in measured:
        by_metric.setdefault(sample["metric"], []).append(sample)
    for metric in ("growth_issuance", "liveness", "generation", "reservation_and_certificate", "direct_delivery_stage", "archive_blob_publication", "commit_and_apply", "refresh", "reconstruct", "epoch_with_growth"):
        rows = by_metric.get(metric, [])
        require(len(rows) == transitions and {s["epoch"] for s in rows} == set(range(1, epochs)), f"{metric}: one measurement per committed epoch required")
        require(all(s["t"] == thresholds[s["epoch"]] and s["N"] == populations[s["epoch"]] for s in rows), f"{metric}: epoch parameters")
    for metric in ("initial_secret_check", "bootstrap_and_initial_issuance", "authentication_key_rotation", "offline_return_and_catchup", "final_reconstruct", "lifecycle"):
        require(len(by_metric.get(metric, [])) == 1, f"{metric}: exactly one observation required")
    lifecycle = by_metric["lifecycle"][0]
    require(lifecycle["data"]["committed_transitions"] == transitions, "lifecycle transition count")
    require(lifecycle["data"]["population_schedule"] == populations and lifecycle["data"]["threshold_schedule"] == thresholds, "lifecycle schedule")
    require(all(s["data"]["classification"] in {"full_registry_deadline_probe", "full_registry_per_participant_deadline_probe"} and s["data"]["eligible"] == populations[s["epoch"]] and s["data"]["offline"] == (offline_participants if s["epoch"] <= 2 else []) for s in by_metric["liveness"]), "full registry liveness and planned participant absence")
    require(all(s["data"].get("aborted_attempt") is False for s in by_metric["generation"]), "aborted generation in normal run")

    for sample in by_metric["liveness"]:
        data = sample["data"]
        if data["classification"] == "full_registry_per_participant_deadline_probe":
            require(data["probed"] == data["eligible"] and data["deadline_scope"] == "per_participant" and data["probe_concurrency"] == 16, "all participants probed with individual response deadlines")
    generation = [e for e in events if e["kind"] == "generation_ready"]
    expected_generation = Counter((dealer, nonce) for dealer in range(1, n + 1) for nonce in range(epochs))
    require(Counter((e["node"], e["data"]["nonce"]) for e in generation) == expected_generation, "each dealer must finish initialization and every generation")
    require(all(e["role"] == "dealer" and e["data"]["broadcast"] == "immutable_anvil_bulletin_board" and e["data"]["accepted_vectors"] == n and e["data"]["qualified"] == list(range(1, n + 1)) and e["data"]["complaints"] == 0 and e["data"]["initial"] == (e["data"]["nonce"] == 0) for e in generation), "normal generation requires all dealer vectors and zero complaints")
    for nonce in range(epochs):
        require(len({e["data"]["target"] for e in generation if e["data"]["nonce"] == nonce}) == 1, "generation target disagreement")
    issued = [e for e in events if e["kind"] == "issued"]
    require(Counter(e["data"]["recipient"] for e in issued) == Counter(range(1, populations[-1] + 1)), "each participant must receive exactly one issued share")
    require(all(e["node"] == 1000 + e["data"]["recipient"] and e["data"]["verification"] == "canonical-transcript-fiat-shamir-msm" and e["data"]["registry_status"] == "issued" and e["data"]["rejected"] == [] for e in issued), "canonical issuance with no invalid dealer partial")
    require(all(not e["data"]["rejected_dealers"] for e in events if e["kind"] == "durable_stage_ack"), "rejected direct partial in normal run")
    require(all(e["data"]["fault"] == "" for e in events if e["kind"] == "token_release"), "faulty token release")
    commits = sorted((trial / "chain").glob("*-canonical-epoch-commit.json"))
    require(len(commits) == transitions and all(int(read(path)["receipt"]["status"], 16) == 1 for path in commits), "successful canonical commit receipts")
    applied = [e for e in events if e["kind"] == "commit_applied"]
    for epoch in range(1, epochs):
        expected = set(range(1, n + 1)) | {1000 + i for i in range(1, populations[epoch] + 1) if i not in offline_participants or epoch > 2}
        rows = [e for e in applied if e["data"]["epoch"] == epoch]
        require(Counter(e["node"] for e in rows) == Counter(expected), "committed state installed exactly once on each online node")

    verify_catchup(by_metric, events, offline_participants, concurrency, n, k, thresholds, populations, explicit_plan)
    oracle = read(trial / "correctness_oracle.json")
    require(oracle["retains_secret"] is False, "owner oracle retains secret")
    reconstructed = [e["data"] for e in events if e["kind"] == "secret_reconstructed"]
    expected_reconstructions = Counter(range(epochs))
    expected_reconstructions[epochs - 1] += 1
    require(Counter(e["epoch"] for e in reconstructed) == expected_reconstructions, "initial, every-epoch and final reconstruction evidence")
    require(all(e["commitment_verified"] is True and e["secret_digest"] == oracle["secret_pair_digest"] for e in reconstructed), "reconstruction oracle digest")
    final = by_metric["final_reconstruct"][0]
    require(final["epoch"] == epochs - 1 and final["data"]["secret_digest"] == oracle["secret_pair_digest"], "final measured secret digest")
    return {"profile": "lifecycle", "trial": trial.name, "n_D": n, "k_D": k, "f_D": f, "injected_faults": 0, "offline_participants": offline_participants, "catchup_applications": 2 * len(offline_participants), "committed_transitions": transitions, "reconstructions": len(reconstructed), "generation_events": len(generation), "issued_events": len(issued), "started_process_instances": starts}


def verify(root):
    root = Path(root)
    run = root / "lifecycle"
    require(not (root / "omission").exists(), "normal benchmark must not contain an omission profile")
    completion, audit = read(run / "completion.json"), read(run / "audit.json")
    require(completion["completed"] is True, "lifecycle: incomplete")
    require(audit["passed"] is True, "lifecycle: raw evidence audit")
    manifest = read(run / "manifest.json")
    require(manifest["implementation"] == "main-lifecycle-v2-normal", "implementation version")
    config = manifest["config"]
    require(config["fault_scenarios"] is False and config["dealer_omission"] is False, "normal-only configuration")
    committees, thresholds, populations = config["committees"], config["thresholds"], config["populations"]
    _, _, delta, outgoing = catchup_plan(config)
    require(manifest["policy"]["delta"] == delta and manifest["policy"]["outgoing_recipient_budget"] == outgoing, "manifest release policy matches configuration")
    require(len(thresholds) == len(populations) and len(thresholds) >= 3, "epoch schedule must support two missed epochs")
    require(config["repeats"] > 0 and committees and all(len(c) == 3 and 1 <= c[1] <= c[0] and 0 <= c[2] < c[1] and 2 * c[2] + c[1] <= c[0] for c in committees), "explicit committee triples and repeats")
    bounds = [{"n_D": n, "k_D": k, "f_D": f} for n, k, f in committees]
    require(manifest["protocol_fault_bounds"] == bounds, "configured protocol fault tolerance; distinct from injected faults")
    expected_trials = {f"n{n}-baseline-trial{trial:03}": (n, k, f) for n, k, f in committees for trial in range(config["repeats"])}
    require(len(expected_trials) == len(committees) * config["repeats"], "ambiguous repeated dealer counts")
    require(completion["baseline_trials"] == len(expected_trials) and completion["fault_trials"] == 0, "completed normal trial counts")
    trials = {path.name: path for path in run.glob("n*-trial*") if path.is_dir()}
    require(set(trials) == set(expected_trials), "missing or unexpected trial directories")
    samples = json_lines(run / "samples.jsonl")
    require(samples and {s["run"] for s in samples} == set(expected_trials), "sample trial coverage")
    evidence = [verify_trial(trials[name], [s for s in samples if s["run"] == name], expected_trials[name], thresholds, populations, config) for name in sorted(trials)]
    require(audit["trials"] == len(evidence) and audit["secret_reconstructions"] == sum(e["reconstructions"] for e in evidence), "audit trial/reconstruction totals")
    result = {"passed": True, "scope": "executed normal lifecycle checks with planned participant absence; no injected faults; not a security proof", "trials": evidence}
    (root / "conformance_checks.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
