"""
m3_demo.py  --  Milestone M3: V1 task evidence. The lying agent is caught.

Demos and expected verdicts:

  Demo 1  Full compliant flow of Figure 3.2: delegate, commit,
          scoped access, execute, signed result, hash match      VERIFIED
  Demo 2  B requests a patient outside its delegated task        BLOCK (scope)
  Demo 3  Compromised B returns a fabricated summary             VIOLATION
  Demo 4  Compromised B replays a previously verified result     VIOLATION
  Demo 5  B cites a task that was never delegated                BLOCK (scope)

With M3, all four attack cases from Chapter 3, Table 3.4 are handled:
normal (allow), unauthorised access (M2), excessive privilege (M2), and
task mismatch, the lying agent (this milestone).

Run with:  python m3_demo.py
"""

from evidence import TaskLedger, canonical_bytes
from identity import Agent, AgentRegistry
from pep import PolicyEnforcementPoint, make_signed_request
from policy import PolicyAdministrator, PolicyDatabase, PolicyEngine
from trust import TrustStore

# ---- The synthetic Records API: tiny, fully synthetic ground truth ----
RECORDS_API = {
    "SYN-0001": ["Aspirin 75mg", "Metformin 500mg"],
    "SYN-0002": ["Amoxicillin 250mg"],
}


def compile_summary(task_id: str, patient: str) -> dict:
    """The deterministic task: read the records, produce the summary.
    The task_id is embedded in the output on purpose, so a result is
    bound to its task and cannot be replayed for another one."""
    return {
        "task_id": task_id,
        "patient": patient,
        "medications": RECORDS_API[patient],
    }


def delegate(pep, ledger, assigner, assignee, task_id, patient):
    """Figure 3.2, step 1: a SIGNED delegation goes through the PEP like
    any other request (agent-to-agent is governed too). On ALLOW, the
    control plane records the commitment. In the simulation the control
    plane holds the ground truth, so it can commit the expected output;
    that is what makes detection measurable."""
    request, signature = make_signed_request(
        assigner, "delegate_task", "records_agent", "delegate",
        task_id=task_id, patient=patient)
    decision = pep.handle(request, signature)
    if decision.outcome == "ALLOW":
        expected = compile_summary(task_id, patient)
        ledger.delegate(task_id, assigner, assignee,
                        "compile_medication_summary", "records_api", "read",
                        {"patient": patient}, expected_output=expected)
    return decision


def show(title, verdict, detail):
    print(f"\n{title}")
    print(f"   verdict: {verdict}  |  {detail}")


def main():
    print("=" * 68)
    print("M3  V1 task evidence: commit, execute, verify")
    print("=" * 68)

    # ---- Control plane assembly (M1 + M2 + the new ledger) --------------
    registry = AgentRegistry()
    policy_db = PolicyDatabase()
    trust = TrustStore()
    ledger = TaskLedger(registry)                       # NEW in M3
    engine = PolicyEngine(registry, policy_db, trust, tasks=ledger)
    pep = PolicyEnforcementPoint(engine, PolicyAdministrator())

    agent_a = Agent("Agent A", "coordinator")
    agent_b = Agent("Agent B", "records")
    for ag in (agent_a, agent_b):
        registry.register(ag)
        policy_db.enrol(ag)
        print(f"Provisioned {ag.name} ({ag.role}): id={ag.agent_id}")

    # ================= Demo 1: the full compliant flow ====================
    print("\nDemo 1: the compliant flow of Figure 3.2, end to end")
    print("   step 1: A delegates T-101 (patient SYN-0001); commitment stored")
    delegate(pep, ledger, agent_a, agent_b, "T-101", "SYN-0001")

    print("   steps 2-5: B requests scoped access; PEP and engine decide")
    request, signature = make_signed_request(
        agent_b, "compile_medication_summary", "records_api", "read",
        task_id="T-101", patient="SYN-0001")
    decision = pep.handle(request, signature)
    print(f"   access: {decision.outcome}  |  {decision.reason}")

    print("   step 6: B executes and returns a SIGNED result")
    result = compile_summary("T-101", "SYN-0001")       # honest execution
    ok, detail = ledger.verify_v1(
        "T-101", agent_b.agent_id, result, agent_b.sign(canonical_bytes(result)))
    print(f"   steps 7-8: {'VERIFIED' if ok else 'VIOLATION'}  |  {detail}")

    # ================= Demo 2: out-of-scope patient ========================
    request, signature = make_signed_request(
        agent_b, "compile_medication_summary", "records_api", "read",
        task_id="T-101", patient="SYN-0002")            # wrong patient
    decision = pep.handle(request, signature)
    show("Demo 2: B requests SYN-0002 under a task delegated for SYN-0001",
         decision.outcome, decision.reason)

    # ================= Demo 3: the lying agent =============================
    delegate(pep, ledger, agent_a, agent_b, "T-102", "SYN-0002")
    fabricated = {"task_id": "T-102", "patient": "SYN-0002",
                  "medications": ["Paracetamol 1g"]}    # never read the records
    ok, detail = ledger.verify_v1(
        "T-102", agent_b.agent_id, fabricated, agent_b.sign(canonical_bytes(fabricated)))
    show("Demo 3: compromised B claims completion with a FABRICATED summary",
         "VERIFIED" if ok else "VIOLATION", detail)
    print("   note: B's signature was VALID. Identity said B sent it;")
    print("   the hash said B lied. That is the case identity alone cannot catch.")

    # ================= Demo 4: replaying an old verified result ============
    delegate(pep, ledger, agent_a, agent_b, "T-103", "SYN-0001")
    replayed = compile_summary("T-101", "SYN-0001")     # T-101's old, once-valid output
    ok, detail = ledger.verify_v1(
        "T-103", agent_b.agent_id, replayed, agent_b.sign(canonical_bytes(replayed)))
    show("Demo 4: compromised B replays T-101's verified result for T-103",
         "VERIFIED" if ok else "VIOLATION", detail)
    print("   note: same patient, same medications, still caught, because the")
    print("   expected output embeds the task_id. Evidence is bound to its task.")

    # ================= Demo 5: a task that was never delegated =============
    request, signature = make_signed_request(
        agent_b, "compile_medication_summary", "records_api", "read",
        task_id="T-999", patient="SYN-0001")
    decision = pep.handle(request, signature)
    show("Demo 5: B requests access citing task T-999, which does not exist",
         decision.outcome, decision.reason)

    print("\nDone. events.log now contains task_commit and evidence_check entries.")


if __name__ == "__main__":
    main()
