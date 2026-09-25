#!/usr/bin/env python3
"""Reject incomplete or misattributed evidence for parallel participant catch-up."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from verify_paper_e2e import catchup_plan, verify_catchup, verify_processes


def recovery_evidence(count=3):
    thresholds, populations = [8, 8, 10, 10], [20, 20, 28, 28]
    participants = list(range(1, count + 1))
    by_metric = {"offline_catchup": [], "participant_catchup": []}
    events = [
        {"kind": "commit_applied", "data": {"epoch": epoch, "target": f"state-{epoch}"}}
        for epoch in (1, 2)
    ]
    for recipient in participants:
        for epoch in (1, 2):
            by_metric["offline_catchup"].append({
                "epoch": epoch, "t": thresholds[epoch], "N": populations[2],
                "data": {"recipient": recipient, "dealers_running": 4,
                         "archive_replicas_running": 2, "localized": 0,
                         "vector_fetches": 0, "records_read": 2, "nonce": epoch},
            })
            events.append({
                "kind": "catchup_applied", "node": 1000 + recipient,
                "role": "participant", "pid": 4000 + recipient, "local_ns": epoch,
                "data": {"nonce": epoch, "target": f"state-{epoch}",
                         "localized": 0, "vector_fetches": 0, "records": 2},
            })
        by_metric["participant_catchup"].append({
            "epoch": 2, "t": thresholds[2], "N": populations[2],
            "data": {"recipient": recipient, "missed_epochs": 2, "completed_epochs": [1, 2],
                     "target_epoch": 2, "records_read": 4},
        })
    by_metric["offline_return_and_catchup"] = [{
        "epoch": 2, "t": thresholds[2], "N": populations[2],
        "data": {"participant_count": count, "participants": participants,
                 "missed_epochs": 2, "concurrency": min(2, count)},
    }]
    return by_metric, events, participants, thresholds, populations


class CatchupEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.metrics, self.events, self.participants, self.thresholds, self.populations = recovery_evidence()

    def verify(self, explicit=True):
        verify_catchup(self.metrics, self.events, self.participants, 2, 4, 2,
                       self.thresholds, self.populations, explicit)

    def test_multiple_participants_with_threshold_update(self):
        self.verify()

    def test_duplicate_recipient_cannot_replace_missing_recipient(self):
        self.metrics["offline_catchup"][-1] = copy.deepcopy(self.metrics["offline_catchup"][1])
        with self.assertRaisesRegex(ValueError, "one recovery per planned participant"):
            self.verify()

    def test_new_measurement_requires_recipient_identity(self):
        del self.metrics["offline_catchup"][0]["data"]["recipient"]
        with self.assertRaisesRegex(ValueError, "identify its recipient"):
            self.verify()

    def test_duplicate_node_event_cannot_replace_other_recipient(self):
        self.events[-1]["node"] = 1001
        with self.assertRaisesRegex(ValueError, "every recipient and missed epoch"):
            self.verify()

    def test_participant_must_apply_missed_epochs_in_order(self):
        self.events[-1], self.events[-2] = self.events[-2], self.events[-1]
        with self.assertRaisesRegex(ValueError, "missed epochs in order"):
            self.verify()

    def test_historical_recovery_must_install_committed_target(self):
        self.events[-1]["data"]["target"] = "uncommitted-state"
        with self.assertRaisesRegex(ValueError, "canonical committed target"):
            self.verify()

    def test_recovery_must_record_historical_threshold(self):
        self.metrics["offline_catchup"][0]["t"] = self.thresholds[2]
        with self.assertRaisesRegex(ValueError, "historical threshold"):
            self.verify()

    def test_missing_individual_total_is_rejected(self):
        self.metrics["participant_catchup"].pop()
        with self.assertRaisesRegex(ValueError, "one total catch-up measurement"):
            self.verify()

    def test_aggregate_must_identify_all_participants(self):
        self.metrics["offline_return_and_catchup"][0]["data"]["participants"] = [1, 1, 3]
        with self.assertRaisesRegex(ValueError, "participant identities"):
            self.verify()

    def test_legacy_single_recipient_evidence(self):
        self.metrics, self.events, self.participants, self.thresholds, self.populations = recovery_evidence(1)
        for sample in self.metrics["offline_catchup"]:
            del sample["data"]["recipient"]
        del self.metrics["participant_catchup"]
        self.metrics["offline_return_and_catchup"][0]["data"] = {"missed_epochs": 2}
        self.verify(explicit=False)

    def test_outgoing_budget_covers_all_returning_participants(self):
        with self.assertRaisesRegex(ValueError, "outgoing recipient budget"):
            catchup_plan({"offline_participants": 16, "outgoing_recipient_budget": 2,
                          "populations": [1024, 1024, 1280, 1280]})


class ProcessEvidenceTests(unittest.TestCase):
    def process_evidence(self, directory, absent):
        roles = {1: "dealer", 8001: "owner", 9001: "archive", 9002: "archive",
                 1001: "participant", 1002: "participant", 1003: "participant"}
        records = [dict(action="start", id=node, role=role, pid=node)
                   for node, role in roles.items()]
        for node in absent:
            records.extend([dict(action="stop", id=node, role=roles[node], pid=node),
                            dict(action="start", id=node, role=roles[node], pid=node + 10000)])
        path = directory / "nodes"
        path.mkdir()
        (path / "process_events.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
        return [dict(kind="process_started", node=r["id"], role=r["role"], pid=r["pid"])
                for r in records if r["action"] == "start"]

    def test_every_planned_participant_restarts_once(self):
        with tempfile.TemporaryDirectory() as directory:
            trial = Path(directory)
            events = self.process_evidence(trial, [1001, 1002])
            self.assertEqual(verify_processes(trial, events, 1, 3, [1, 2]), 9)

    def test_unplanned_absence_rejected_even_with_same_count(self):
        with tempfile.TemporaryDirectory() as directory:
            trial = Path(directory)
            events = self.process_evidence(trial, [1001, 1003])
            with self.assertRaisesRegex(ValueError, "unplanned participant stop"):
                verify_processes(trial, events, 1, 3, [1, 2])


if __name__ == "__main__":
    unittest.main()
