"""
pep.py  --  Policy Enforcement Point (M2).

Chapter 3, Figure 3.1: the PEP is the checkpoint in the path of every
request. Nothing reaches a resource or another agent without crossing it.
It enforces decisions; it does not make them.

The PEP also carries the replay defence promised in M1 (section 3.5):
every request carries a fresh timestamp and a one-time nonce. A request
older than the freshness window is rejected as stale; a nonce seen before
is rejected as a replay, even though its signature is perfectly valid.
That last point matters: replay is the attack that identity checking
alone cannot stop, because the attacker resends a genuinely signed
message.
"""

import json
import uuid
from datetime import datetime, timezone

from logger import log_event
from policy import Decision, PolicyAdministrator, PolicyEngine

FRESHNESS_SECONDS = 300  # accept requests up to five minutes old


def canonical_bytes(payload: dict) -> bytes:
    """Fixed, repeatable serialisation (same rule as M1): identical data
    always produces identical bytes, so identical signatures and hashes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_signed_request(agent, task_type, resource, action, task_id, **extra):
    """Client-side helper: build a request with a fresh timestamp and a
    one-time nonce, and sign its canonical bytes. Returns (request, signature).
    In a deployed system this code lives inside each agent; it sits here so
    the prototype keeps message rules in one place."""
    request = {
        "agent_id": agent.agent_id,
        "task_type": task_type,
        "resource": resource,
        "action": action,
        "task_id": task_id,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nonce": uuid.uuid4().hex,
        **extra,
    }
    return request, agent.sign(canonical_bytes(request))


class PolicyEnforcementPoint:
    def __init__(self, engine: PolicyEngine, administrator: PolicyAdministrator):
        self.engine = engine
        self.administrator = administrator
        self._seen_nonces = set()

    def handle(self, request: dict, signature: bytes) -> Decision:
        """Intercept one request: freshness, replay, then the engine's
        three-step decision, then enforcement and logging."""
        agent_id = request.get("agent_id", "unknown")

        # Freshness: reject requests outside the time window.
        sent = datetime.fromisoformat(request["timestamp"])
        age = abs((datetime.now(timezone.utc) - sent).total_seconds())
        if age > FRESHNESS_SECONDS:
            decision = Decision("BLOCK", f"stale: request is {age:.0f}s old")
            return self._finish(agent_id, request, decision)

        # Replay: a nonce is one-time; seeing it again means a resent message.
        if request["nonce"] in self._seen_nonces:
            decision = Decision("BLOCK", "replay: nonce already used")
            return self._finish(agent_id, request, decision)
        self._seen_nonces.add(request["nonce"])

        # Decide (engine), then enforce the outcome (administrator).
        decision = self.engine.decide(request, canonical_bytes(request), signature)
        decision = self.administrator.grant(decision, request)
        return self._finish(agent_id, request, decision)

    def _finish(self, agent_id: str, request: dict, decision: Decision) -> Decision:
        log_event(
            "decision", agent_id, decision.outcome,
            f"{decision.reason} | {request.get('task_type')} {request.get('action')} {request.get('resource')}",
        )
        return decision
