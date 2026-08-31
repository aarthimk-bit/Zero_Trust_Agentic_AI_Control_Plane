"""
m6_experiment.py  --  Comparative evaluation (Milestone M6).

This is the study that produces Chapter 5. It compares three conditions on
identical, seeded task streams, so the value of each mechanism appears as a
measured difference rather than a claim.

  BASELINE   Identity plus a static role allowlist, modelled on deployed
             agent practice (pairing and allowlists, no task binding, no
             evidence verification, no dynamic trust).
  SCOPED     The baseline plus delegated task-scope authorisation, and nothing
             else. This condition exists so that the contribution of task
             scoping can be separated from the contribution of task evidence:
             baseline to scoped isolates scoping, scoped to V1/V2 isolates
             evidence verification. Without it, moving from baseline to V1
             changes two controls at once and the comparison is confounded.
  V1         Scoped plus output-hash task evidence.
  V2         Scoped plus execution-record evidence verification.

Three studies:
  Study A  Main comparison. Three conditions, ten seeds, 15% attack rate,
           40% of honest records tasks non-deterministic.
  Study B  Attack-rate sensitivity. V2 across rates from 5% to 25%.
  Study C  Trust-parameter sensitivity. V2 with trust updates enabled,
           varying the reward increment and violation penalty, to confirm
           the qualitative findings do not depend on one trust setting
           (Chapter 3, section 3.10, threats to validity).

Overhead is measured as Table 3.5 defines it:
  computational  = condition latency MINUS baseline latency (added latency);
  communication  = control-plane messages per completed task, and bytes,
                   split into ordinary result payload and the additional
                   verification evidence, both relative to the baseline.
Byte counts cover serialised result and evidence payloads only; signatures,
delegation messages, and request traffic are excluded, and are identical
across conditions in any case.

Detection is measured with trust held constant in Studies A and B, so a
condition is judged on what it detects rather than on trust movement, which
Study C and M5 examine separately. All data is synthetic (Data Protection
Act 2018).

Run with:  python m6_experiment.py
Outputs:   results_m6_main.csv, results_m6_sensitivity.csv,
           results_m6_trust_sensitivity.csv
"""

import csv
import random
import statistics as stats
import time

import logger
logger.ECHO = False

from agents_m6 import (PROCEDURE_RECORDS, PROCEDURE_SCHEDULE, expected_v1_output,
                       fabricated_records_output, honest_records_output,
                       honest_schedule_output)
from evidence import canonical_bytes
from evidence_v2 import TaskLedgerV2
from identity import Agent, AgentRegistry
from pep import PolicyEnforcementPoint, make_signed_request
from policy import PolicyAdministrator, PolicyDatabase, PolicyEngine
from scenario_m6 import build_scenario
from trust import TrustStore

N_TASKS, N_PATIENTS = 200, 50
NONDET_FRACTION = 0.40
SEEDS = list(range(42, 52))          # ten seeds


def build(condition, trust_params=None, update_trust=False):
    """One control plane for a run. The condition selects how much of the
    framework is active, which is the independent variable of the study."""
    registry = AgentRegistry()
    policy_db = PolicyDatabase()
    trust = TrustStore()
    if trust_params:                                  # Study C overrides
        trust.REWARD = trust_params["reward"]
        trust.VIOLATION_FACTOR = trust_params["violation"]
    ledger = TaskLedgerV2(registry, trust=trust if update_trust else None)
    # Baseline has no task binding: the engine runs without the ledger, so
    # there is no scope check. Scoped, V1 and V2 all pass the ledger, which
    # enables the task-scope check; they differ only in what happens to the
    # returned evidence.
    engine = PolicyEngine(registry, policy_db, trust,
                          tasks=None if condition == "baseline" else ledger)
    pep = PolicyEnforcementPoint(engine, PolicyAdministrator())
    a, b, cc = Agent("Agent A", "coordinator"), Agent("Agent B", "records"), Agent("Agent C", "scheduler")
    for ag in (a, b, cc):
        registry.register(ag)
        policy_db.enrol(ag)
    return dict(registry=registry, ledger=ledger, pep=pep, trust=trust, a=a, b=b, c=cc)


def _sizes(result, record, condition):
    """Return (result_bytes, verification_bytes). The baseline transmits a
    result but no verification evidence, so its verification bytes are zero.
    V1's evidence is the hashed result itself, already counted as result
    payload, so its additional verification bytes are zero too. V2 adds the
    execution record."""
    rb = len(canonical_bytes(result))
    vb = len(canonical_bytes(record)) if condition == "V2" else 0
    return rb, vb


def run_records(w, task, records_api, condition, rng):
    """One records task. Returns (status, messages, result_bytes, verif_bytes)."""
    a, b, ledger, pep = w["a"], w["b"], w["ledger"], w["pep"]
    msgs = 0

    req, sig = make_signed_request(a, "delegate_task", "records_agent", "delegate",
                                   task_id=task["task_id"], patient=task["patient"])
    msgs += 1
    if pep.handle(req, sig).outcome == "ALLOW" and condition != "baseline":
        params = {"patient": task["patient"], "fields": "medications"}
        if condition == "scoped":
            ledger.delegate_scope_only(
                task["task_id"], a, b, PROCEDURE_RECORDS,
                "records_api", "read", {"patient": task["patient"]}
            )
        elif condition == "V1":
            ledger.delegate(
                task["task_id"], a, b, PROCEDURE_RECORDS,
                "records_api", "read", {"patient": task["patient"]},
                expected_output=expected_v1_output(task, records_api)
            )
        else:
            ledger.delegate_scope_only(
                task["task_id"], a, b, PROCEDURE_RECORDS,
                "records_api", "read", {"patient": task["patient"]}
            )
            ledger.commit_v2(
                task["task_id"], PROCEDURE_RECORDS, params,
                records_api[task["patient"]]
            )

    patient = task["wrong_patient"] if task["label"] == "unauth_access" else task["patient"]
    req, sig = make_signed_request(b, PROCEDURE_RECORDS, "records_api", "read",
                                   task_id=task["task_id"], patient=patient)
    msgs += 1
    decision = pep.handle(req, sig)
    if decision.outcome != "ALLOW":
        return ("blocked" if decision.outcome == "BLOCK" else "flagged"), msgs, 0, 0

    if task["label"] == "task_mismatch":
        result, record = fabricated_records_output(task)
    else:
        result, record = honest_records_output(task, records_api, rng)
    rb, vb = _sizes(result, record, condition)
    msgs += 1                                    # result / evidence submission

    if condition in ("baseline", "scoped"):
        # No evidence verification in either condition: the returned result is
        # accepted on the strength of identity and policy alone.
        return "accepted", msgs, rb, vb
    if condition == "V1":
        ok, _ = ledger.verify_v1(task["task_id"], b.agent_id, result,
                                 b.sign(canonical_bytes(result)))
    else:
        ok, _ = ledger.verify_v2(task["task_id"], b.agent_id, record, result,
                                 b.sign(canonical_bytes(record)))
    return ("verified" if ok else "violation"), msgs, rb, vb


def run_schedule(w, task, condition):
    """One schedule task. Returns (status, messages, result_bytes, verif_bytes)."""
    a, c, ledger, pep = w["a"], w["c"], w["ledger"], w["pep"]
    msgs = 0
    req, sig = make_signed_request(a, "delegate_task", "scheduler_agent", "delegate",
                                   task_id=task["task_id"], patient=task["patient"])
    msgs += 1
    if pep.handle(req, sig).outcome == "ALLOW" and condition != "baseline":
        expected = {"task_id": task["task_id"], "patient": task["patient"], "slot": task["slot"]}
        if condition == "scoped":
            ledger.delegate_scope_only(
                task["task_id"], a, c, PROCEDURE_SCHEDULE,
                "calendar", "write", {"patient": task["patient"]}
            )
        elif condition == "V1":
            ledger.delegate(
                task["task_id"], a, c, PROCEDURE_SCHEDULE,
                "calendar", "write", {"patient": task["patient"]},
                expected_output=expected
            )
        else:
            ledger.delegate_scope_only(
                task["task_id"], a, c, PROCEDURE_SCHEDULE,
                "calendar", "write", {"patient": task["patient"]}
            )
            ledger.commit_v2(
                task["task_id"], PROCEDURE_SCHEDULE,
                {"patient": task["patient"]}, task["slot"]
            )

    if task["label"] == "excess_priv":
        req, sig = make_signed_request(c, PROCEDURE_SCHEDULE, "records_api", "write",
                                       task_id=task["task_id"], patient=task["patient"])
        msgs += 1
        d = pep.handle(req, sig)
        return ("blocked" if d.outcome == "BLOCK" else "flagged"), msgs, 0, 0

    req, sig = make_signed_request(c, PROCEDURE_SCHEDULE, "calendar", "write",
                                   task_id=task["task_id"], patient=task["patient"])
    msgs += 1
    d = pep.handle(req, sig)
    if d.outcome != "ALLOW":
        return ("blocked" if d.outcome == "BLOCK" else "flagged"), msgs, 0, 0

    result, record = honest_schedule_output(task)
    rb, vb = _sizes(result, record, condition)
    msgs += 1
    if condition in ("baseline", "scoped"):
        return "accepted", msgs, rb, vb
    if condition == "V1":
        ok, _ = ledger.verify_v1(task["task_id"], c.agent_id, result, c.sign(canonical_bytes(result)))
    else:
        ok, _ = ledger.verify_v2(task["task_id"], c.agent_id, record, result,
                                 c.sign(canonical_bytes(record)))
    return ("verified" if ok else "violation"), msgs, rb, vb


COMPLETED = {"verified", "accepted"}
def is_correct(label, status):
    if label == "normal":
        return status in COMPLETED
    if label in ("unauth_access", "excess_priv"):
        return status == "blocked"
    if label == "task_mismatch":
        return status == "violation"
    return False


def run_once(condition, attack_rate, seed, trust_params=None, update_trust=False):
    records_api, tasks = build_scenario(N_TASKS, N_PATIENTS, attack_rate, NONDET_FRACTION, seed)
    w = build(condition, trust_params, update_trust)
    rng = random.Random(seed + 99)
    rows, lat, msgs, rbytes, vbytes = [], [], [], [], []
    for task in tasks:
        t0 = time.perf_counter()
        if task["kind"] == "records":
            status, m, rb, vb = run_records(w, task, records_api, condition, rng)
        else:
            status, m, rb, vb = run_schedule(w, task, condition)
        lat.append((time.perf_counter() - t0) * 1000)
        msgs.append(m); rbytes.append(rb); vbytes.append(vb)
        rows.append((task["label"], status, is_correct(task["label"], status)))

    completed = [i for i, r in enumerate(rows) if r[1] in COMPLETED]
    normals = [r for r in rows if r[0] == "normal"]
    attacks = [r for r in rows if r[0] != "normal"]
    sel = lambda lab, pred: (lambda s: sum(pred(r) for r in s) / len(s) if s else 0.0)(
        [r for r in rows if r[0] == lab])

    b_id = w["b"].agent_id
    return {
        "condition": condition, "attack_rate": attack_rate, "seed": seed,
        "reward": w["trust"].REWARD, "violation_factor": w["trust"].VIOLATION_FACTOR,
        "accuracy": sum(r[2] for r in rows) / len(rows),
        "unauth_block": sel("unauth_access", lambda r: r[1] == "blocked"),
        "excess_block": sel("excess_priv", lambda r: r[1] == "blocked"),
        "mismatch_detect": sel("task_mismatch", lambda r: r[1] == "violation"),
        "normal_completion": sum(r[1] in COMPLETED for r in normals) / len(normals),
        "mismatch_contained": sel("task_mismatch", lambda r: r[1] in ("violation", "blocked")),
        "false_positive": sum(r[1] not in COMPLETED for r in normals) / len(normals),
        "false_negative": sum(r[1] in COMPLETED for r in attacks) / len(attacks),
        "latency_ms": sum(lat) / len(lat),
        "latency_sd": stats.pstdev(lat) if len(lat) > 1 else 0.0,
        "messages_per_completed": (sum(msgs[i] for i in completed) / len(completed)) if completed else 0.0,
        "result_bytes_per_completed": (sum(rbytes[i] for i in completed) / len(completed)) if completed else 0.0,
        "verif_bytes_per_completed": (sum(vbytes[i] for i in completed) / len(completed)) if completed else 0.0,
        "final_trust_b": w["trust"].score(b_id),
        "time_to_quarantine": w["trust"].time_to_quarantine(b_id),
        "quarantine_reached": w["trust"].time_to_quarantine(b_id) is not None,
    }


def mean(runs, key):
    vals = [r[key] for r in runs if r[key] is not None]
    return stats.mean(vals) if vals else float("nan")


def main():
    print("=" * 78)
    print("Extended comparative evaluation: baseline vs scoped vs V1 vs V2")
    print(f"     {len(SEEDS)} seeds, {N_TASKS} tasks, 15% attacks, "
          f"{int(NONDET_FRACTION*100)}% non-deterministic honest records tasks")
    print("=" * 78)

    # ---- Study A --------------------------------------------------------
    main_rows, S = [], {}
    for cond in ("baseline", "scoped", "V1", "V2"):
        runs = [run_once(cond, 0.15, s) for s in SEEDS]
        main_rows += runs
        S[cond] = runs
    base_lat = mean(S["baseline"], "latency_ms")
    base_msg = mean(S["baseline"], "messages_per_completed")
    base_byt = mean(S["baseline"], "result_bytes_per_completed")

    def col(key, fmt="{:.3f}"):
        return "  ".join(fmt.format(mean(S[c], key)).rjust(9) for c in ("baseline", "scoped", "V1", "V2"))

    print(f"\nStudy A  Mean over {len(SEEDS)} seeds   baseline     scoped         V1         V2")
    print("-" * 78)
    print(f"Accuracy                     {col('accuracy')}")
    print(f"Unauthorised-access block    {col('unauth_block')}")
    print(f"Excessive-privilege block    {col('excess_block')}")
    print(f"Task-mismatch detection      {col('mismatch_detect')}")
    print(f"False-positive rate          {col('false_positive')}")
    print(f"False-negative rate          {col('false_negative')}")
    print("-" * 78)
    print("Overhead, as defined in Table 3.5 (relative to baseline)")
    print("Latency SD (ms)              " + col("latency_sd", "{:.3f}"))
    print("Added latency (ms)           " + "  ".join(
        "{:+.3f}".format(mean(S[c], "latency_ms") - base_lat).rjust(9) for c in ("baseline", "scoped", "V1", "V2")))
    print("Messages / completed task    " + col("messages_per_completed", "{:.2f}"))
    print("Added messages vs baseline   " + "  ".join(
        "{:+.2f}".format(mean(S[c], "messages_per_completed") - base_msg).rjust(9) for c in ("baseline", "scoped", "V1", "V2")))
    print("Result payload bytes         " + col("result_bytes_per_completed", "{:.0f}"))
    print("Verification evidence bytes  " + col("verif_bytes_per_completed", "{:.0f}"))
    print("Added bytes vs baseline      " + "  ".join(
        "{:+.0f}".format((mean(S[c],"result_bytes_per_completed")+mean(S[c],"verif_bytes_per_completed")) - base_byt).rjust(9)
        for c in ("baseline", "scoped", "V1", "V2")))
    print("-" * 78)
    with open("results_m6_main.csv", "w", newline="", encoding="utf-8") as f:
        wtr = csv.DictWriter(f, fieldnames=list(main_rows[0].keys())); wtr.writeheader(); wtr.writerows(main_rows)

    # ---- Study B --------------------------------------------------------
    print(f"\nStudy B  V2 across attack rates (mean over {len(SEEDS)} seeds)")
    print("-" * 78)
    print("rate   accuracy   unauth_block   mismatch_detect   false_neg   latency_ms")
    sens = []
    for ar in (0.05, 0.10, 0.15, 0.20, 0.25):
        runs = [run_once("V2", ar, s) for s in SEEDS]; sens += runs
        print(f"{ar:>4.0%}     {mean(runs,'accuracy'):.3f}        {mean(runs,'unauth_block'):.3f}"
              f"          {mean(runs,'mismatch_detect'):.3f}            {mean(runs,'false_negative'):.3f}"
              f"       {mean(runs,'latency_ms'):.3f}")
    with open("results_m6_sensitivity.csv", "w", newline="", encoding="utf-8") as f:
        wtr = csv.DictWriter(f, fieldnames=list(sens[0].keys())); wtr.writeheader(); wtr.writerows(sens)

    # ---- Study C: trust-parameter sensitivity ---------------------------
    print(f"\nStudy C  Trust-parameter sensitivity, V2 with trust updates enabled")
    print("-" * 78)
    print("reward  violation   normal      mismatch    mismatch    quarantine   conditional")
    print("                    completion  detection   contained   reached      mean TTQ")
    trust_rows = []
    for reward, violation in ((0.01, 0.5), (0.02, 0.5), (0.02, 0.7), (0.02, 0.9), (0.05, 0.7)):
        params = {"reward": reward, "violation": violation}
        runs = [run_once("V2", 0.15, s, trust_params=params, update_trust=True) for s in SEEDS]
        trust_rows += runs
        reached = [r for r in runs if r["quarantine_reached"]]
        ttq = mean(reached, "time_to_quarantine") if reached else float("nan")
        ttq_s = f"{ttq:.1f}" if reached else "n/a"
        print(f"{reward:>5.2f}  {violation:>8.2f}   {mean(runs,'normal_completion'):>10.3f}"
              f"  {mean(runs,'mismatch_detect'):>10.3f}  {mean(runs,'mismatch_contained'):>10.3f}"
              f"  {len(reached):>6d}/{len(runs):<4d} {ttq_s:>11}")
    print("-" * 78)
    print("Note: trust updates are live in Study C. Once a compromised agent is")
    print("quarantined, its later tasks are blocked before reaching the evidence")
    print("check, so evidence-level DETECTION falls while CONTAINMENT stays high,")
    print("and the agent's honest tasks are blocked too, lowering normal completion.")
    print("Conditional mean TTQ averages only the runs that reached quarantine.")
    with open("results_m6_trust_sensitivity.csv", "w", newline="", encoding="utf-8") as f:
        wtr = csv.DictWriter(f, fieldnames=list(trust_rows[0].keys())); wtr.writeheader(); wtr.writerows(trust_rows)

    total = len(main_rows) + len(sens) + len(trust_rows)
    print(f"\n{total} seeded runs completed "
          f"({len(main_rows)} in Study A, {len(sens)} in Study B, {len(trust_rows)} in Study C).")
    print("Per-run results written to results_m6_main.csv, results_m6_sensitivity.csv, "
          "results_m6_trust_sensitivity.csv")


if __name__ == "__main__":
    main()
