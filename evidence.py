"""
evidence.py  --  Task ledger and V1 task evidence verification (Milestone M3).

This module is the heart of the dissertation (Chapter 3, section 3.7).
It answers the research question in code: can the control plane verify,
through hash-based task evidence, that an agent's returned work
corresponds to its assigned task?

The pattern is commit, execute, verify:

  COMMIT   When Agent A delegates task T, the control plane stores a hash
           of the task specification (which fixes the procedure, its
           parameters, and the input scope) and, because the task is
           deterministic, a hash of the expected output. Hashes are
           SHA-256, the same FIPS 180-4 family used for agent IDs.
  EXECUTE  The assignee performs the task under a scoped grant (M2).
  VERIFY   The assignee returns a signed result. The control plane hashes
           it and compares against the commitment. Match: VERIFIED.
           Mismatch: VIOLATION, and the result never reaches Agent A.

Two design points worth understanding:

  - The expected output embeds the task_id, so a previously verified
    result replayed for a new task can never match the new commitment.
    Evidence is bound to its task.
  - Results are signed. The signature says WHO submitted the evidence;
    the hash says whether the evidence is TRUE. A compromised insider
    produces a valid signature and a failing hash, which is exactly the
    lying-agent case.

In the simulation the control plane holds the ground truth (the synthetic
records), which is what makes detection measurable. In deployment the
expected output is not always known in advance; that is the limit of V1
and the reason V2 (execution-evidence digest) exists.
"""

import hashlib
import json

from identity import AgentRegistry, verify_signature
from logger import log_event


def canonical_bytes(payload) -> bytes:
    """Same serialisation rule as pep.py, kept local to avoid a circular
    import: identical data always produces identical bytes."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """SHA-256 fingerprint (FIPS 180-4), printed as hex."""
    return hashlib.sha256(data).hexdigest()


class TaskLedger:
    """
    The evidence store from Figure 3.1: delegation records and their hash
    commitments. It is also a contextual data source for the policy
    engine: a request citing a task can be checked against what was
    actually delegated (check_scope), which upgrades least privilege from
    role level to task level.
    """

    def __init__(self, registry: AgentRegistry):
        self.registry = registry
        self._tasks = {}  # task_id -> delegation record

    # ---------------- COMMIT ----------------
    def delegate(self, task_id, assigner, assignee, task_type, resource,
                 action, params: dict, expected_output=None):
        """Record a delegation and its commitments."""
        spec = {
            "task_id": task_id,
            "assigner": assigner.agent_id,
            "assignee": assignee.agent_id,
            "task_type": task_type,
            "resource": resource,
            "action": action,
            "params": params,
        }
        record = dict(spec)
        record["spec_hash"] = sha256_hex(canonical_bytes(spec))
        record["expected_hash"] = (
            sha256_hex(canonical_bytes(expected_output))
            if expected_output is not None else None
        )
        record["status"] = "delegated"
        self._tasks[task_id] = record
        log_event("task_commit", assigner.agent_id, "COMMITTED",
                  f"task={task_id} spec_hash={record['spec_hash'][:16]}..")
        return record

    def delegate_scope_only(self, task_id, assigner, assignee, task_type,
                            resource, action, params: dict):
        """Register delegation metadata for task-scope authorisation only.

        This condition deliberately stores no V1 expected-output hash and no
        V2 execution commitment, allowing task scoping to be evaluated
        independently from evidence verification.
        """
        record = {
            "task_id": task_id,
            "assigner": assigner.agent_id,
            "assignee": assignee.agent_id,
            "task_type": task_type,
            "resource": resource,
            "action": action,
            "params": params,
            "status": "delegated",
        }
        self._tasks[task_id] = record
        return record

    # ---------------- SCOPE (used by the policy engine, step 2b) ----------------
    def check_scope(self, request) -> tuple[bool, str]:
        """A request citing a delegated task must match the delegation:
        right assignee, right task type, right resource and action, and
        the right patient. This closes the M2 gap where policy was only
        role-level."""
        task_id = request.get("task_id")
        record = self._tasks.get(task_id)
        if record is None:
            return False, f"scope: no delegated task '{task_id}'"
        if record["assignee"] != request["agent_id"]:
            return False, f"scope: task {task_id} was not assigned to this agent"
        for field in ("task_type", "resource", "action"):
            if record[field] != request.get(field):
                return False, f"scope: {field} differs from the delegation"
        if "patient" in record["params"] and request.get("patient") != record["params"]["patient"]:
            return False, "scope: patient differs from the delegated task"
        return True, "in scope"

    # ---------------- VERIFY (V1) ----------------
    def verify_v1(self, task_id, agent_id, result, signature) -> tuple[bool, str]:
        """V1: hash the signed result and compare with the commitment."""
        record = self._tasks.get(task_id)
        if record is None:
            return False, f"evidence: no delegated task '{task_id}'"

        # Evidence must come from the agent to which the task was delegated.
        # A valid signature from another registered agent is not sufficient.
        if record["assignee"] != agent_id:
            log_event("evidence_check", agent_id, "REJECTED",
                      f"task={task_id} result submitted by non-assignee")
            return False, "V1: result submitter is not the delegated assignee"

        # Evidence is only evidence if we know who submitted it.
        result_bytes = canonical_bytes(result)
        if not verify_signature(self.registry, agent_id, result_bytes, signature):
            log_event("evidence_check", agent_id, "REJECTED",
                      f"task={task_id} result signature invalid")
            return False, "evidence rejected: result signature does not verify"

        if record["expected_hash"] is None:
            return False, "V1 needs a deterministic expected output (V2 covers the rest)"

        returned_hash = sha256_hex(result_bytes)
        if returned_hash == record["expected_hash"]:
            record["status"] = "verified"
            log_event("evidence_check", agent_id, "VERIFIED",
                      f"task={task_id} V1 hash match")
            return True, "V1: returned work matches the commitment"

        record["status"] = "violation"
        log_event("evidence_check", agent_id, "VIOLATION",
                  f"task={task_id} V1 hash mismatch")
        return False, "V1: returned work does NOT match the commitment"
