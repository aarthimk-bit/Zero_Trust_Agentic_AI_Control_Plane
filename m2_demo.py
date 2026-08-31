"""
m2_demo.py  --  Milestone M2: the policy path.

Seven demos exercise the full decision order (identity, policy, trust)
plus the replay defence. Expected outcomes:

  Demo 1  B reads records for its task            ALLOW   (all checks pass)
  Demo 2  C tries to read patient records         BLOCK   (unauthorised access case)
  Demo 3  C tries to write the clinical record    BLOCK   (excessive privilege case)
  Demo 4  C books an appointment at trust 0.55    FLAG    (write tier is 0.70)
  Demo 5  same request after C earns trust 0.75   ALLOW   (tier now met)
  Demo 6  Demo 1's exact message resent           BLOCK   (replay caught by nonce)
  Demo 7  imposter signs as Agent A               BLOCK   (identity, as in M1)

Demos 2 and 3 are two of the four attack cases from Chapter 3, Table 3.4,
already handled correctly. Run with:  python m2_demo.py
"""

from identity import Agent, AgentRegistry
from pep import PolicyEnforcementPoint, make_signed_request
from policy import PolicyAdministrator, PolicyDatabase, PolicyEngine
from trust import TrustStore


def show(title, decision):
    print(f"\n{title}")
    print(f"   outcome: {decision.outcome}  |  {decision.reason}")
    if decision.scope:
        print(f"   grant:   {decision.scope}")


def main():
    print("=" * 68)
    print("M2  Policy enforcement: PEP, policy engine, administrator, database")
    print("=" * 68)

    # ---- Control plane assembly -----------------------------------------
    registry = AgentRegistry()      # WHO exists (identity, from M1)
    policy_db = PolicyDatabase()    # WHAT each role may do (new in M2)
    trust = TrustStore()            # HOW FAR each agent is trusted (placeholder)
    engine = PolicyEngine(registry, policy_db, trust)
    pep = PolicyEnforcementPoint(engine, PolicyAdministrator())

    # ---- Agents: register identity AND enrol in policy, two separate acts
    agent_a = Agent("Agent A", "coordinator")
    agent_b = Agent("Agent B", "records")
    agent_c = Agent("Agent C", "scheduler")
    for ag in (agent_a, agent_b, agent_c):
        registry.register(ag)   # identity: who this is
        policy_db.enrol(ag)     # authority: what its role permits
        print(f"Provisioned {ag.name} ({ag.role}): id={ag.agent_id}")

    # ---- Demo 1: B reads records for its assigned task -------------------
    req1, sig1 = make_signed_request(
        agent_b, "compile_medication_summary", "records_api", "read",
        task_id="T-001", patient="SYN-0001")
    show("Demo 1: Agent B reads records for task T-001", pep.handle(req1, sig1))

    # ---- Demo 2: unauthorised access (attack case) ------------------------
    req, sig = make_signed_request(
        agent_c, "compile_medication_summary", "records_api", "read",
        task_id="T-002", patient="SYN-0001")
    show("Demo 2: Agent C (scheduler) tries to read patient records", pep.handle(req, sig))

    # ---- Demo 3: excessive privilege (attack case) -------------------------
    req, sig = make_signed_request(
        agent_c, "book_followup", "records_api", "write", task_id="T-003")
    show("Demo 3: Agent C tries to WRITE the clinical record", pep.handle(req, sig))

    # ---- Demo 4: permitted action, but trust tier not yet met -------------
    # New agents start trusted at the write tier (0.70). To show the tier
    # working, put C just below it first, as if an earlier event had cost it
    # trust. M5 makes this movement automatic.
    trust.set_score(agent_c.agent_id, 0.55)
    req, sig = make_signed_request(
        agent_c, "book_followup", "calendar", "write", task_id="T-004")
    show("Demo 4: Agent C books an appointment at trust 0.55 (below the 0.70 write tier)",
         pep.handle(req, sig))

    # ---- Demo 5: the same action once trust has been earned ---------------
    trust.set_score(agent_c.agent_id, 0.75)   # M5 will earn this via +0.02 steps
    req, sig = make_signed_request(
        agent_c, "book_followup", "calendar", "write", task_id="T-005")
    show("Demo 5: same request after C's trust reaches 0.75", pep.handle(req, sig))

    # ---- Demo 6: replay of Demo 1's genuinely signed message --------------
    show("Demo 6: Demo 1's exact signed message resent (replay)", pep.handle(req1, sig1))

    # ---- Demo 7: imposter, as in M1, now blocked inside the full path -----
    mallory = Agent("Mallory", "unknown")
    req, _ = make_signed_request(
        agent_a, "delegate_task", "records_agent", "delegate", task_id="T-006")
    from pep import canonical_bytes
    forged = mallory.sign(canonical_bytes(req))
    show("Demo 7: imposter signs Agent A's request with her own key", pep.handle(req, forged))

    print("\nDone. events.log now also contains 'decision' entries with causes.")


if __name__ == "__main__":
    main()
