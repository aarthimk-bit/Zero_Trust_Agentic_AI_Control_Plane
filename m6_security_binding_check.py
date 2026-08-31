"""Focused regression checks for M6 evidence binding.

Run after copying the final M6 files:
    python m6_security_binding_check.py

The script confirms that V1 and V2 accept evidence from the delegated
assignee and reject evidence signed by another registered agent. It also
checks V2 task-ID and output-digest binding.
"""

from agents_m6 import PROCEDURE_RECORDS
from evidence import TaskLedger, canonical_bytes, sha256_hex
from evidence_v2 import TaskLedgerV2
from identity import Agent, AgentRegistry


def main():
    registry = AgentRegistry()
    assigner = Agent("Coordinator", "coordinator")
    assignee = Agent("Records", "records")
    other = Agent("Scheduler", "scheduler")
    for agent in (assigner, assignee, other):
        registry.register(agent)

    result = {"task_id": "T-SEC-1", "patient": "SYN-0001",
              "medications": ["Drug A"]}

    v1 = TaskLedger(registry)
    v1.delegate("T-SEC-1", assigner, assignee, PROCEDURE_RECORDS,
                "records_api", "read", {"patient": "SYN-0001"},
                expected_output=result)
    ok, _ = v1.verify_v1("T-SEC-1", assignee.agent_id, result,
                         assignee.sign(canonical_bytes(result)))
    assert ok, "V1 should accept the delegated assignee"
    ok, reason = v1.verify_v1("T-SEC-1", other.agent_id, result,
                              other.sign(canonical_bytes(result)))
    assert not ok and "delegated assignee" in reason, reason

    v2 = TaskLedgerV2(registry)
    params = {"patient": "SYN-0001", "fields": "medications"}
    inputs = ["Drug A"]
    v2.delegate("T-SEC-2", assigner, assignee, PROCEDURE_RECORDS,
                "records_api", "read", {"patient": "SYN-0001"})
    v2.commit_v2("T-SEC-2", PROCEDURE_RECORDS, params, inputs)
    result2 = {"task_id": "T-SEC-2", "patient": "SYN-0001",
               "medications": inputs}
    record = {
        "task_id": "T-SEC-2",
        "procedure": PROCEDURE_RECORDS,
        "parameters": params,
        "inputs_content": inputs,
        "output_digest": sha256_hex(canonical_bytes(result2)),
    }
    ok, _ = v2.verify_v2("T-SEC-2", assignee.agent_id, record, result2,
                         assignee.sign(canonical_bytes(record)))
    assert ok, "V2 should accept the delegated assignee"

    ok, reason = v2.verify_v2("T-SEC-2", other.agent_id, record, result2,
                              other.sign(canonical_bytes(record)))
    assert not ok and "delegated assignee" in reason, reason

    wrong_task = dict(record, task_id="T-WRONG")
    ok, reason = v2.verify_v2("T-SEC-2", assignee.agent_id, wrong_task, result2,
                              assignee.sign(canonical_bytes(wrong_task)))
    assert not ok and "task identifier" in reason, reason

    changed_result = dict(result2, medications=["Different Drug"])
    ok, reason = v2.verify_v2("T-SEC-2", assignee.agent_id, record, changed_result,
                              assignee.sign(canonical_bytes(record)))
    assert not ok and "output digest" in reason, reason

    print("PASS: M6 evidence binding checks completed successfully.")


if __name__ == "__main__":
    main()
