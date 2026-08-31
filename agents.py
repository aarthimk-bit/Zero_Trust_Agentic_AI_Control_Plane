"""
agents.py  --  Scenario agent behaviours, honest and compromised (M4).

The Agent class from identity.py stays what it is: a name, a role, and a
key pair. WHAT an agent does in the scenario lives here, as behaviour
functions, so honest and compromised conduct sit side by side and the
ground-truth label decides which one runs.

A design point worth noticing: the compromised behaviours use perfectly
valid signatures. The attacker here is an insider or a hijacked agent,
which is exactly the threat model of Chapter 3, section 3.3.
"""

from evidence import canonical_bytes
from pep import make_signed_request


def run_records_task(task, agent_b, pep, ledger, records_api):
    """The records agent's turn. Returns (final_status, message_count).

    honest          request the delegated patient, read, return true summary
    unauth_access   request a DIFFERENT patient under the same task
    task_mismatch   request honestly, then return a fabricated summary
    """
    label = task["label"]
    requested_patient = task["wrong_patient"] if label == "unauth_access" else task["patient"]

    request, signature = make_signed_request(
        agent_b, "compile_medication_summary", "records_api", "read",
        task_id=task["task_id"], patient=requested_patient)
    decision = pep.handle(request, signature)
    messages = 1
    if decision.outcome != "ALLOW":
        # BLOCK or FLAG ends the task here; nothing was executed.
        return ("blocked" if decision.outcome == "BLOCK" else "flagged", messages)

    if label == "task_mismatch":
        # The lying agent: never reads the records, fabricates the result,
        # signs it validly, and claims completion.
        result = {"task_id": task["task_id"], "patient": task["patient"],
                  "medications": ["Placebo 0mg"]}
    else:
        # Honest execution: read the records, build the summary.
        result = {"task_id": task["task_id"], "patient": task["patient"],
                  "medications": records_api[task["patient"]]}

    ok, _ = ledger.verify_v1(task["task_id"], agent_b.agent_id,
                             result, agent_b.sign(canonical_bytes(result)))
    messages += 1
    return ("verified" if ok else "violation", messages)


def run_schedule_task(task, agent_c, pep, ledger, calendar):
    """The scheduler's turn. Returns (final_status, message_count).

    honest       write the delegated slot to the calendar, return the booking
    excess_priv  attempt to WRITE the clinical record instead
    """
    if task["label"] == "excess_priv":
        request, signature = make_signed_request(
            agent_c, "book_followup", "records_api", "write",
            task_id=task["task_id"], patient=task["patient"])
        decision = pep.handle(request, signature)
        return ("blocked" if decision.outcome == "BLOCK" else "flagged", 1)

    request, signature = make_signed_request(
        agent_c, "book_followup", "calendar", "write",
        task_id=task["task_id"], patient=task["patient"])
    decision = pep.handle(request, signature)
    messages = 1
    if decision.outcome != "ALLOW":
        return ("blocked" if decision.outcome == "BLOCK" else "flagged", messages)

    calendar[task["task_id"]] = task["slot"]           # the actual write
    result = {"task_id": task["task_id"], "patient": task["patient"],
              "slot": task["slot"]}
    ok, _ = ledger.verify_v1(task["task_id"], agent_c.agent_id,
                             result, agent_c.sign(canonical_bytes(result)))
    messages += 1
    return ("verified" if ok else "violation", messages)
