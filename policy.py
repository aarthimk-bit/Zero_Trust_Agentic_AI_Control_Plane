"""
policy.py  --  Policy database, policy engine, policy administrator.

Chapter 3, section 3.6. Together the engine and administrator form the
Policy Decision Point (PDP):
  - the POLICY DATABASE is the memory: who has which role, what each role
    may do, and the minimum trust tier per action;
  - the POLICY ENGINE decides every request in a fixed order:
        1. identity   2. policy (and, from M3, 2b. task scope)   3. trust
    A fixed order means every denial has exactly one attributable cause,
    which is what the evaluation metrics count in Chapter 5;
  - the POLICY ADMINISTRATOR turns an ALLOW into a scoped, task-bound
    grant, and nothing else.

M3 change: the engine can now consult the task ledger as a contextual
data source (exactly the role NIST SP 800-207 gives context feeding the
policy engine). A request that cites a delegated task must match that
delegation: right assignee, right task, right resource and action, right
patient. Least privilege moves from role level to task level.

Zero Trust default: anything not explicitly permitted is denied. The
database enumerates permissions, never prohibitions.
"""

from dataclasses import dataclass

from identity import AgentRegistry, verify_signature
from trust import TrustStore


@dataclass
class Decision:
    outcome: str          # "ALLOW", "BLOCK", or "FLAG"
    reason: str           # single attributable cause, human readable
    scope: dict | None = None   # filled by the administrator on ALLOW


class PolicyDatabase:
    """Roles, permissions, and trust tiers (Table 3.2 in Chapter 3)."""

    def __init__(self):
        self._roles = {}  # agent_id -> role, set at enrolment
        # Permitted (role, task_type, resource, action) tuples. Absent = denied.
        self._permissions = {
            ("coordinator", "delegate_task", "records_agent",   "delegate"),
            ("coordinator", "delegate_task", "scheduler_agent", "delegate"),
            ("records",     "compile_medication_summary", "records_api", "read"),
            ("scheduler",   "book_followup", "calendar", "write"),
        }
        # Minimum trust tier per action (section 3.8): writes need more
        # earned trust than reads.
        self._tiers = {"read": 0.4, "delegate": 0.4, "write": 0.7}

    def enrol(self, agent) -> None:
        """Record what an agent MAY DO. Deliberately separate from
        identity registration (WHO the agent is): knowing an identity
        never implies granting it authority."""
        self._roles[agent.agent_id] = agent.role

    def role_of(self, agent_id: str) -> str | None:
        return self._roles.get(agent_id)

    def permits(self, role, task_type, resource, action) -> bool:
        return (role, task_type, resource, action) in self._permissions

    def min_tier(self, action: str) -> float:
        return self._tiers.get(action, 1.0)  # unknown actions need maximum trust


class PolicyEngine:
    """Step 2 of Figure 3.1: decides, never enforces."""

    def __init__(self, registry: AgentRegistry, db: PolicyDatabase,
                 trust: TrustStore, tasks=None):
        self.registry = registry
        self.db = db
        self.trust = trust
        # M3: the task ledger, a contextual data source. Optional, so the
        # M2 demo runs unchanged without it.
        self.tasks = tasks

    def decide(self, request: dict, message: bytes, signature: bytes) -> Decision:
        agent_id = request["agent_id"]

        # 1. Identity: the signature must verify against the REGISTERED key.
        if not verify_signature(self.registry, agent_id, message, signature):
            return Decision("BLOCK", "identity: signature does not verify against the registered key")

        # 1b. Quarantine: once trust falls below the quarantine threshold,
        # every request is blocked pending review.
        if self.trust.is_quarantined(agent_id):
            return Decision("BLOCK",
                f"trust: score {self.trust.score(agent_id):.2f} below quarantine threshold")

        # 2. Policy: the (task, resource, action) must be permitted for the role.
        role = self.db.role_of(agent_id)
        if role is None or not self.db.permits(role, request["task_type"], request["resource"], request["action"]):
            return Decision("BLOCK",
                f"policy: role '{role}' is not permitted to {request['action']} {request['resource']}")

        # 2b (M3). Task scope: a request citing a delegated task must match
        # the delegation. Delegations themselves are exempt, because a
        # delegation is what CREATES the task record.
        if self.tasks is not None and request.get("task_id") and request.get("action") != "delegate":
            in_scope, reason = self.tasks.check_scope(request)
            if not in_scope:
                return Decision("BLOCK", reason)

        # 3. Trust: the agent's score must meet the action's minimum tier.
        score = self.trust.score(agent_id)
        needed = self.db.min_tier(request["action"])
        if score < needed:
            return Decision("FLAG",
                f"trust: score {score:.2f} below tier {needed:.2f} for '{request['action']}'")

        return Decision("ALLOW", "granted")


class PolicyAdministrator:
    """Turns an ALLOW into a scoped grant; opens nothing on BLOCK or FLAG."""

    def grant(self, decision: Decision, request: dict) -> Decision:
        if decision.outcome == "ALLOW":
            decision.scope = {
                "task_id": request["task_id"],
                "resource": request["resource"],
                "action": request["action"],
                "expiry": "ends with the task",
            }
        return decision
