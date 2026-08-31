"""
evidence_v2.py  --  V2 execution-evidence verification (Milestone M6).

Chapter 3, section 3.7 defines two verification variants. V1 (in
evidence.py) compares the returned OUTPUT against a committed expected
output. It is exact and cheap, but it needs a deterministic output: if an
honest task legitimately varies its result (a free-text clinical note, a
timestamp), V1 cannot tell honest variation from fabrication and flags the
honest work.

V2 verifies the PROCEDURE instead of the output value. At delegation the
control plane commits the fields that a correct execution must reproduce:
the task identifier, the procedure, its parameters, and the content of the
inputs the task should read. On completion the executor returns an
execution record carrying those four fields plus a digest of the output it
produced. Verification has two parts. First, V2 recomputes the commitment
from the record's four committed fields and compares it with the stored
commitment. Second, V2 recomputes the digest of the result actually
submitted and compares it with the output_digest inside the signed record,
which binds the record to that result and prevents an agent from returning
one output while describing another. The output digest is NOT compared
against any committed value, because an honest output may legitimately
vary; that is precisely what lets V2 verify non-deterministic work.

This is a subclass of TaskLedger, so nothing in M1 to M5 changes. The V1
path, the scope check, and the trust wiring are inherited unchanged.

Compatibility note: the constructor calls super().__init__(registry) and
stores trust locally, so this class works with either the original M3
TaskLedger (which takes registry only) or any later version.

Trade-off, measured in M6: V2 covers non-deterministic tasks that V1
cannot, at the cost of a larger evidence message (it carries the execution
record in addition to the result).
"""

from evidence import TaskLedger, canonical_bytes, sha256_hex, verify_signature
from logger import log_event

# The record fields fixed at delegation and therefore compared at verification.
COMMITTED_FIELDS = ("task_id", "procedure", "parameters", "inputs_content")


class TaskLedgerV2(TaskLedger):
    """Adds a V2 commitment at delegation and a verify_v2 verdict."""

    def __init__(self, registry, trust=None):
        # Call the base with registry only: compatible with every version
        # of TaskLedger in this project.
        super().__init__(registry)
        self.trust = trust
        self._v2_commitments = {}   # task_id -> hash of the committed fields

    def commit_v2(self, task_id, procedure, parameters, inputs_content):
        """Store the execution commitment: what the task should do, with
        which parameters, over which input content. inputs_content is the
        actual data an honest agent must read, so an agent that skips
        reading cannot reproduce it."""
        commitment = {"task_id": task_id, "procedure": procedure,
                      "parameters": parameters, "inputs_content": inputs_content}
        self._v2_commitments[task_id] = sha256_hex(canonical_bytes(commitment))

    def verify_v2(self, task_id, agent_id, execution_record, result, signature):
        """Two checks. (a) The committed fields of the execution record must
        reproduce the commitment, so the agent must show the right procedure,
        parameters, and input content. (b) The digest inside the signed record
        must match the digest of the result actually submitted, binding record
        to result. The output VALUE is never compared against a committed
        value, so honest non-deterministic results pass."""
        expected = self._v2_commitments.get(task_id)
        if expected is None:
            return False, f"V2: no execution commitment for task '{task_id}'"

        task_record = self._tasks.get(task_id)
        if task_record is None:
            return False, f"V2: no delegated task '{task_id}'"

        # Evidence must be submitted by the task's delegated assignee. A
        # different registered agent may have a valid signature of its own,
        # but it is not authorised to attest to this task.
        if task_record["assignee"] != agent_id:
            log_event("evidence_check", agent_id, "REJECTED",
                      f"task={task_id} evidence submitted by non-assignee")
            return False, "V2: evidence submitter is not the delegated assignee"

        # The task identifier is part of the signed execution record. Do not
        # overwrite it with the caller's argument: compare it explicitly.
        if execution_record.get("task_id") != task_id:
            log_event("evidence_check", agent_id, "VIOLATION",
                      f"task={task_id} execution-record task identifier mismatch")
            if self.trust is not None:
                self.trust.penalise_violation(agent_id)
            return False, "V2: execution-record task identifier does not match"

        record_bytes = canonical_bytes(execution_record)
        if not verify_signature(self.registry, agent_id, record_bytes, signature):
            log_event("evidence_check", agent_id, "REJECTED",
                      f"task={task_id} V2 record signature invalid")
            return False, "evidence rejected: execution-record signature does not verify"

        # (b) Bind the record to the result actually submitted: the signed
        # record's output_digest must match a fresh digest of that result.
        actual_digest = sha256_hex(canonical_bytes(result))
        if execution_record.get("output_digest") != actual_digest:
            log_event("evidence_check", agent_id, "VIOLATION",
                      f"task={task_id} V2 output digest mismatch")
            if self.trust is not None:
                self.trust.penalise_violation(agent_id)
            return False, "V2: output digest does not match the returned result"

        # (a) Recompute the commitment from what the agent claims it did.
        claimed = {f: execution_record.get(f) for f in COMMITTED_FIELDS}
        if sha256_hex(canonical_bytes(claimed)) == expected:
            log_event("evidence_check", agent_id, "VERIFIED",
                      f"task={task_id} V2 execution-record match")
            if self.trust is not None:
                self.trust.reward(agent_id)
            return True, "V2: execution record matches the commitment"

        log_event("evidence_check", agent_id, "VIOLATION",
                  f"task={task_id} V2 execution-record mismatch")
        if self.trust is not None:
            self.trust.penalise_violation(agent_id)
        return False, "V2: execution record does NOT match the commitment"
