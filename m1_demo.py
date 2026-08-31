"""
m1_demo.py  --  Milestone M1: agent identity and signed messages.

What this run demonstrates (requirement R1 in Chapter 3):
  Demo 1  A legitimate signed request from Agent A verifies.       PASS expected
  Demo 2  The same request, altered in transit, is rejected.       FAIL expected
  Demo 3  An imposter claiming Agent A's identity is rejected.     FAIL expected

The two rejections are the point: security code is only shown to work when
it refuses bad input.

Run with:  python m1_demo.py
"""

import json

from identity import Agent, AgentRegistry, verify_signature
from logger import log_event


def canonical_bytes(payload: dict) -> bytes:
    """
    Turn a task request into bytes in a fixed, repeatable way.
    sort_keys=True means the same data always produces the same bytes, so
    the same signature. The same idea, canonical serialisation, carries
    the execution-evidence digest (V2) in a later milestone.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main():
    print("=" * 68)
    print("M1  Agent identity and signed messages")
    print("=" * 68)

    # ---- Trusted provisioning: create and register the agents ----------
    # Registration is the trusted step in the threat model (section 3.3):
    # keys recorded here are the ground-truth identities.
    control_plane = AgentRegistry()
    agent_a = Agent(name="Agent A", role="coordinator")
    agent_b = Agent(name="Agent B", role="records")
    control_plane.register(agent_a)
    control_plane.register(agent_b)
    print(f"\nRegistered {agent_a.name} (coordinator): id={agent_a.agent_id}")
    print(f"Registered {agent_b.name} (records):     id={agent_b.agent_id}")

    # ---- Agent A builds and signs one task request ----------------------
    request = {
        "from": agent_a.agent_id,
        "to": agent_b.agent_id,
        "task": "compile_medication_summary",
        "patient": "SYN-0001",                # synthetic identifier only
        "timestamp": "2026-07-10T09:00:00Z",  # replay defence arrives in M2
    }
    message = canonical_bytes(request)
    signature = agent_a.sign(message)

    # ---- Demo 1: the legitimate request ---------------------------------
    print("\nDemo 1: legitimate signed request from Agent A")
    ok = verify_signature(control_plane, agent_a.agent_id, message, signature)
    outcome = "PASS" if ok else "FAIL"
    print(f"   identity check: {outcome}")
    log_event("identity_check", agent_a.agent_id, outcome, "legitimate request")

    # ---- Demo 2: the same request, tampered in transit ------------------
    print("\nDemo 2: request altered in transit (patient changed)")
    tampered = dict(request, patient="SYN-0002")   # one field changed
    ok = verify_signature(
        control_plane, agent_a.agent_id, canonical_bytes(tampered), signature
    )
    outcome = "PASS" if ok else "FAIL"
    print(f"   identity check: {outcome}  (FAIL is correct: the bytes no longer match the signature)")
    log_event("identity_check", agent_a.agent_id, outcome, "tampered request rejected")

    # ---- Demo 3: an imposter claims to be Agent A ------------------------
    print("\nDemo 3: imposter with its own keys claims Agent A's identity")
    mallory = Agent(name="Mallory", role="unknown")   # never registered as A
    forged = mallory.sign(message)
    ok = verify_signature(control_plane, agent_a.agent_id, message, forged)
    outcome = "PASS" if ok else "FAIL"
    print(f"   identity check: {outcome}  (FAIL is correct: signature does not match A's registered key)")
    log_event("identity_check", agent_a.agent_id, outcome, "imposter rejected")

    print("\nDone. Open events.log in this folder to see the append-only audit trail.")


if __name__ == "__main__":
    main()
