"""
m7_forged_evidence.py  --  Study D: adversarial robustness of task evidence.

Purpose. The main studies inject a dishonest agent that never reads the
delegated inputs. That agent is detected by both verification variants. This
study asks a harder question, raised as a limitation in the dissertation and
requested in supervision: can V2 distinguish a truthful signed execution
record from a self-consistent but dishonest one?

Method. For every task-mismatch episode in the same ten seeded task streams
used by Study A, three execution behaviours are submitted to both verifiers
under identical commitments:

  honest        a genuine deterministic execution (control case)
  naive         fabrication without reading the delegated inputs
  forged        fabrication by an agent that DID read the delegated inputs and
                reports an internally consistent record over its false result

Each behaviour is verified twice, once under V1 (output-hash comparison) and
once under V2 (execution-record comparison), on a freshly built ledger so no
state carries between checks. Detection means the verifier returned a
violation. For the honest control, detection would be a false positive.

Run with:  python m7_forged_evidence.py
Output:    a summary table on screen and per-case rows in results_study_d_forged_evidence.csv
"""

import csv
import statistics as stats

import logger
logger.ECHO = False

from agents_forged import (forged_consistent_output, honest_deterministic_output,
                           naive_fabricated_output)
from agents_m6 import PROCEDURE_RECORDS, expected_v1_output
from evidence import canonical_bytes
from evidence_v2 import TaskLedgerV2
from identity import Agent, AgentRegistry
from scenario_m6 import build_scenario

N_TASKS, N_PATIENTS = 200, 50
ATTACK_RATE, NONDET_FRACTION = 0.15, 0.40
SEEDS = list(range(42, 52))          # the same ten seeds as Study A

BEHAVIOURS = ("honest", "naive", "forged")
VERIFIERS = ("V1", "V2")


def commit_task(ledger, a, b, task, records_api):
    """Store the V1 and V2 commitments for one delegated task, exactly as the
    control plane does in the main experiment."""
    params = {"patient": task["patient"], "fields": "medications"}
    ledger.delegate(task["task_id"], a, b, PROCEDURE_RECORDS, "records_api", "read",
                    {"patient": task["patient"]},
                    expected_output=expected_v1_output(task, records_api))
    ledger.commit_v2(task["task_id"], PROCEDURE_RECORDS, params,
                     records_api[task["patient"]])


def make_output(behaviour, task, records_api):
    if behaviour == "honest":
        return honest_deterministic_output(task, records_api)
    if behaviour == "naive":
        return naive_fabricated_output(task)
    return forged_consistent_output(task, records_api)


def run_case(behaviour, verifier, task, records_api):
    """One verification. Returns True when the verifier reported a violation."""
    registry = AgentRegistry()
    a, b = Agent("Agent A", "coordinator"), Agent("Agent B", "records")
    registry.register(a); registry.register(b)
    ledger = TaskLedgerV2(registry, trust=None)
    commit_task(ledger, a, b, task, records_api)

    result, record = make_output(behaviour, task, records_api)
    if verifier == "V1":
        ok, _ = ledger.verify_v1(task["task_id"], b.agent_id, result,
                                 b.sign(canonical_bytes(result)))
    else:
        ok, _ = ledger.verify_v2(task["task_id"], b.agent_id, record, result,
                                 b.sign(canonical_bytes(record)))
    return (not ok)      # detection = verification rejected the submission


def main():
    print("=" * 78)
    print("Study D  Adversarial robustness of task evidence")
    print(f"     {len(SEEDS)} seeds, task-mismatch episodes from the Study A streams")
    print("=" * 78)

    rows = []
    for seed in SEEDS:
        records_api, tasks = build_scenario(N_TASKS, N_PATIENTS, ATTACK_RATE,
                                            NONDET_FRACTION, seed)
        mismatches = [t for t in tasks
                      if t["label"] == "task_mismatch" and t["kind"] == "records"]
        for task in mismatches:
            for behaviour in BEHAVIOURS:
                for verifier in VERIFIERS:
                    rows.append({"seed": seed, "task_id": task["task_id"],
                                 "behaviour": behaviour, "verifier": verifier,
                                 "detected": run_case(behaviour, verifier,
                                                      task, records_api)})

    per_seed = {}
    for b in BEHAVIOURS:
        for v in VERIFIERS:
            by_seed = {}
            for r in rows:
                if r["behaviour"] == b and r["verifier"] == v:
                    by_seed.setdefault(r["seed"], []).append(r["detected"])
            per_seed[(b, v)] = [sum(x) / len(x) for x in by_seed.values()]

    n_cases = len([r for r in rows if r["behaviour"] == "honest"
                   and r["verifier"] == "V1"])
    print(f"\nEpisodes tested per behaviour and verifier: {n_cases}"
          f"  ({n_cases // len(SEEDS)} per seed)\n")
    print(f"{'Execution behaviour':<44}{'V1':>10}{'V2':>12}")
    print("-" * 78)
    labels = {"honest": "Honest deterministic execution (control)",
              "naive":  "Naive fabrication, inputs not read",
              "forged": "Internally consistent forgery, inputs read"}
    for b in BEHAVIOURS:
        m1 = stats.mean(per_seed[(b, "V1")]); m2 = stats.mean(per_seed[(b, "V2")])
        note = "  <- false positives" if b == "honest" else "  <- detection rate"
        print(f"{labels[b]:<44}{m1:>10.3f}{m2:>12.3f}{note}")
    print("-" * 78)
    print("Values are the mean proportion of episodes the verifier rejected,")
    print("averaged over ten seeds. For the honest control a non-zero value")
    print("would be a false positive; for the two dishonest behaviours a value")
    print("of 1.000 is complete detection and 0.000 is complete evasion.")

    with open("results_study_d_forged_evidence.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print(f"\n{len(rows)} verification cases written to results_study_d_forged_evidence.csv")


if __name__ == "__main__":
    main()
