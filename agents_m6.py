"""
agents_m6.py  --  Agent behaviours returning execution evidence (M6).

Each honest execution returns three things:
  - result            the work product, with a varying note when the task
                      is non-deterministic;
  - execution_record  what V2 checks, aligned with the Chapter 3 definition:
                      task identifier, procedure, parameters applied,
                      inputs read, and a digest of the output;
  - byte counts       so result payload and verification evidence can be
                      measured separately (Table 3.5, communication overhead).

A compromised agent fabricates: it never reads the records, so its result
is wrong and its execution record cannot reproduce the committed input
content. V1 catches this on deterministic tasks but false-alarms on honest
non-deterministic ones; V2 catches it on both without false alarms.

Limitation, stated plainly and carried into Chapter 5: the execution record
is produced and signed by the agent under evaluation. V2 detects the
modelled dishonest agent because that agent cannot reproduce input content
it never read. An adversary able to obtain the true inputs by other means
could forge a plausible record, which is why V3 spot-checking exists.
"""

import random

from evidence import canonical_bytes, sha256_hex

PROCEDURE_RECORDS = "compile_medication_summary"
PROCEDURE_SCHEDULE = "book_followup"


def _record(task_id, procedure, parameters, inputs_content, output):
    """Build a Chapter 3 compliant execution record."""
    return {
        "task_id": task_id,
        "procedure": procedure,
        "parameters": parameters,
        "inputs_content": inputs_content,
        "output_digest": sha256_hex(canonical_bytes(output)),
    }


def honest_records_output(task, records_api, rng):
    """Read the real record and build the summary. Non-deterministic tasks
    append a note that varies per run."""
    meds = records_api[task["patient"]]
    params = {"patient": task["patient"], "fields": "medications"}
    result = {"task_id": task["task_id"], "patient": task["patient"], "medications": meds}
    if not task["deterministic"]:
        result["note"] = f"reviewed at t={rng.randint(1000, 9999)}"   # varies honestly
    return result, _record(task["task_id"], PROCEDURE_RECORDS, params, meds, result)


def fabricated_records_output(task):
    """The lying agent: never reads the record, so neither its output nor
    its claimed input content can match the commitment."""
    params = {"patient": task["patient"], "fields": "medications"}
    result = {"task_id": task["task_id"], "patient": task["patient"],
              "medications": ["Placebo 0mg"]}
    return result, _record(task["task_id"], PROCEDURE_RECORDS, params, ["(not read)"], result)


def honest_schedule_output(task):
    """Book the delegated slot and report it."""
    params = {"patient": task["patient"]}
    result = {"task_id": task["task_id"], "patient": task["patient"], "slot": task["slot"]}
    return result, _record(task["task_id"], PROCEDURE_SCHEDULE, params, task["slot"], result)


def expected_v1_output(task, records_api):
    """What the control plane commits for V1: the deterministic part only.
    It cannot know a future varying note, which is exactly why V1 fails on
    non-deterministic tasks."""
    return {"task_id": task["task_id"], "patient": task["patient"],
            "medications": records_api[task["patient"]]}
