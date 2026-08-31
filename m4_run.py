"""
m4_run.py  --  Experiment runner (Milestones M4 and M5).

Runs the Chapter 3 scenario end to end and reports the Table 3.5 metrics
against ground truth. Everything is seeded, so every run is reproducible.

Two separate experiments, because the research question has two halves and
conflating them is a measurement error:

  Experiment 1  DETECTION QUALITY (trust held constant).
                Given a task, does the framework classify it correctly?
                Trust does not change here, so an agent's honest tasks are
                judged on their own merits and are never pre-blocked because
                of a different, earlier task. This isolates what identity,
                policy, and V1 evidence DETECT. It produces the headline
                accuracy, block rate, detection rate, and false-positive and
                false-negative figures, and results_m4.csv.

  Experiment 2  TRUST DYNAMICS (trust updates enabled).
                A persistently compromised records agent commits a violation
                on every attack-labelled task. This measures how quickly the
                M5 trust rules drive it to quarantine (time-to-quarantine)
                and confirms quarantine then holds. This answers the "dynamic
                trust adjusts authority over time" half of the question.

Why separate: an agent is a long-lived identity that handles many tasks. If
trust from a compromised task pre-blocks that same agent's later honest
tasks, those honest tasks would be counted as false positives, which
measures persistence, not detection. Chapter 3 reports detection and trust
dynamics as distinct results for exactly this reason.

M5 note: trust is EARNED, not warm-started. Every agent starts at 0.70 (the
write tier: a newly enrolled agent is trusted by the control plane and must
maintain that trust). The M6 grid adds the baseline and V2 conditions and
ten-seed repetition.

Run with:  python m4_run.py
"""

import csv
import time

import logger
logger.ECHO = False   # silence per-event echo; the audit FILE is unchanged

from agents import run_records_task, run_schedule_task
from evidence import TaskLedger
from identity import Agent, AgentRegistry
from pep import PolicyEnforcementPoint, make_signed_request
from policy import PolicyAdministrator, PolicyDatabase, PolicyEngine
from scenario import make_patients, make_task_stream
from trust import TrustStore

# ---- Experiment parameters (Chapter 3, sections 3.9 and 3.10) ----------
N_TASKS = 200
N_PATIENTS = 50
ATTACK_RATE = 0.15
SEED = 42

# Ground truth: what each label SHOULD end as.
EXPECTED = {
    "normal": "verified",
    "unauth_access": "blocked",
    "excess_priv": "blocked",
    "task_mismatch": "violation",
}


def delegate_and_commit(w, agent_a, assignee, task):
    """Figure 3.2 step 1 for every task: a signed delegation through the PEP,
    then the commitment computed from ground truth."""
    target = "records_agent" if task["kind"] == "records" else "scheduler_agent"
    request, signature = make_signed_request(
        agent_a, "delegate_task", target, "delegate",
        task_id=task["task_id"], patient=task["patient"])
    decision = w["pep"].handle(request, signature)
    if decision.outcome != "ALLOW":
        return
    if task["kind"] == "records":
        expected = {"task_id": task["task_id"], "patient": task["patient"],
                    "medications": w["records_api"][task["patient"]]}
        w["ledger"].delegate(task["task_id"], agent_a, assignee,
                             "compile_medication_summary", "records_api", "read",
                             {"patient": task["patient"]}, expected_output=expected)
    else:
        expected = {"task_id": task["task_id"], "patient": task["patient"],
                    "slot": task["slot"]}
        w["ledger"].delegate(task["task_id"], agent_a, assignee,
                             "book_followup", "calendar", "write",
                             {"patient": task["patient"]}, expected_output=expected)


def build_world():
    """Fresh, independent control plane, agents, and synthetic data, so the
    two experiments never share state."""
    registry = AgentRegistry()
    policy_db = PolicyDatabase()
    trust = TrustStore()
    ledger = TaskLedger(registry)
    engine = PolicyEngine(registry, policy_db, trust, tasks=ledger)
    pep = PolicyEnforcementPoint(engine, PolicyAdministrator())
    agent_a = Agent("Agent A", "coordinator")
    agent_b = Agent("Agent B", "records")
    agent_c = Agent("Agent C", "scheduler")
    for ag in (agent_a, agent_b, agent_c):
        registry.register(ag)
        policy_db.enrol(ag)
    records_api = make_patients(N_PATIENTS, SEED)
    tasks = make_task_stream(N_TASKS, ATTACK_RATE, SEED, records_api)
    return dict(registry=registry, policy_db=policy_db, trust=trust, ledger=ledger,
                pep=pep, agent_a=agent_a, agent_b=agent_b, agent_c=agent_c,
                records_api=records_api, calendar={}, tasks=tasks)


def run_stream(w, update_trust):
    """Execute the task stream once. update_trust selects the experiment."""
    rows = []
    for task in w["tasks"]:
        assignee = w["agent_b"] if task["kind"] == "records" else w["agent_c"]
        t0 = time.perf_counter()
        delegate_and_commit(w, w["agent_a"], assignee, task)
        if task["kind"] == "records":
            status, msgs = run_records_task(task, w["agent_b"], w["pep"], w["ledger"], w["records_api"])
        else:
            status, msgs = run_schedule_task(task, w["agent_c"], w["pep"], w["ledger"], w["calendar"])
        latency_ms = (time.perf_counter() - t0) * 1000
        if update_trust:
            actor = assignee.agent_id
            if status == "verified":
                w["trust"].reward(actor)
            elif status == "violation":
                w["trust"].penalise_violation(actor)
            elif status == "flagged":
                w["trust"].penalise_flag(actor)
        rows.append({
            "task_id": task["task_id"], "kind": task["kind"],
            "ground_truth": task["label"], "final_status": status,
            "correct": (status == EXPECTED[task["label"]]),
            "latency_ms": round(latency_ms, 3), "messages": msgs,
            "trust_after": round(w["trust"].score(assignee.agent_id), 3),
        })
    return rows


def report_detection(rows):
    total = len(rows)
    by = lambda label: [r for r in rows if r["ground_truth"] == label]
    normals = by("normal")
    attacks = [r for r in rows if r["ground_truth"] != "normal"]
    blockable = by("unauth_access") + by("excess_priv")
    mismatch = by("task_mismatch")

    acc = sum(r["correct"] for r in rows) / total
    block = sum(r["final_status"] == "blocked" for r in blockable) / len(blockable)
    detect = sum(r["final_status"] == "violation" for r in mismatch) / len(mismatch)
    fp = sum(r["final_status"] != "verified" for r in normals) / len(normals)
    fn = sum(r["final_status"] == "verified" for r in attacks) / len(attacks)
    mean_ms = sum(r["latency_ms"] for r in rows) / total
    mean_msgs = sum(r["messages"] for r in rows) / total
    n = lambda label: len(by(label))

    print(f"\nExperiment 1  Detection quality (trust held constant)")
    print(f"Tasks: {total} (normal {n('normal')} | unauth_access {n('unauth_access')}"
          f" | excess_priv {n('excess_priv')} | task_mismatch {n('task_mismatch')})")
    print(f"Seed: {SEED}   Attack rate: {ATTACK_RATE:.0%}")
    print("-" * 68)
    print(f"Policy enforcement accuracy  : {sum(r['correct'] for r in rows)}/{total} = {acc:.3f}")
    print(f"Unauthorised-action block    : {sum(r['final_status']=='blocked' for r in blockable)}/{len(blockable)} = {block:.3f}")
    print(f"Task-mismatch detection (V1) : {sum(r['final_status']=='violation' for r in mismatch)}/{len(mismatch)} = {detect:.3f}")
    print(f"False positives              : {sum(r['final_status']!='verified' for r in normals)}/{len(normals)} = {fp:.3f}")
    print(f"False negatives              : {sum(r['final_status']=='verified' for r in attacks)}/{len(attacks)} = {fn:.3f}")
    print(f"Mean latency per task        : {mean_ms:.2f} ms")
    print(f"Mean messages per task       : {mean_msgs:.2f}")
    print("-" * 68)


def report_trust(rows, trust, b_id):
    ttq = trust.time_to_quarantine(b_id)
    print(f"\nExperiment 2  Trust dynamics (trust updates enabled)")
    print("-" * 68)
    print(f"Records agent B final trust  : {trust.score(b_id):.2f}"
          f"  ({'quarantined' if trust.is_quarantined(b_id) else 'active'})")
    print(f"Time-to-quarantine           : "
          + (f"{ttq} interactions from first violation" if ttq is not None
             else "did not reach quarantine"))
    # Confirm quarantine holds: B's honest tasks after quarantine are blocked.
    print("-" * 68)


def main():
    print("=" * 68)
    print("M4/M5  Zero Trust framework experiment")
    print("=" * 68)

    # Experiment 1: detection quality, trust constant.
    w1 = build_world()
    rows1 = run_stream(w1, update_trust=False)
    report_detection(rows1)
    with open("results_m4.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows1[0].keys()))
        writer.writeheader()
        writer.writerows(rows1)
    print("Per-task detection results written to results_m4.csv")

    # Experiment 2: trust dynamics, trust updates enabled.
    w2 = build_world()
    rows2 = run_stream(w2, update_trust=True)
    report_trust(rows2, w2["trust"], w2["agent_b"].agent_id)


if __name__ == "__main__":
    main()
