import asyncio
import csv

from mcp import Client
from mcp.server import MCPServer

from m6_experiment import build, make_signed_request


# ---------------------------------------------------------------------------
# Synthetic protected resources exposed as real MCP tools.
# ---------------------------------------------------------------------------

PATIENT_RECORDS = {
    "SYN-0001": {"medications": ["Aspirin 75mg", "Atorvastatin 20mg"]},
    "SYN-0002": {"medications": ["Metformin 500mg"]},
    "SYN-0003": {"medications": ["Ramipril 5mg"]},
}

CALENDAR = {}

INVOCATIONS = {
    "records_read": 0,
    "calendar_write": 0,
}

server = MCPServer("Study E Zero Trust MCP Pilot")


@server.tool()
def records_read(patient_id: str) -> dict:
    """Protected synthetic patient-record read."""
    INVOCATIONS["records_read"] += 1
    record = PATIENT_RECORDS.get(patient_id)
    if record is None:
        return {"status": "not_found", "patient_id": patient_id}
    return {
        "status": "ok",
        "patient_id": patient_id,
        "medications": record["medications"],
    }


@server.tool()
def calendar_write(patient_id: str, slot: str, context: str = "") -> dict:
    """Protected synthetic appointment-calendar write."""
    INVOCATIONS["calendar_write"] += 1
    CALENDAR[patient_id] = slot
    return {
        "status": "booked",
        "patient_id": patient_id,
        "slot": slot,
        "context_received": bool(context),
    }


# ---------------------------------------------------------------------------
# Existing Zero Trust control plane.
# MCP is the invocation interface; it does not replace the PEP/PDP.
# ---------------------------------------------------------------------------

def delegate_records(world, task_id, patient):
    a, b = world["a"], world["b"]

    req, sig = make_signed_request(
        a,
        "delegate_task",
        "records_agent",
        "delegate",
        task_id=task_id,
        patient=patient,
    )
    decision = world["pep"].handle(req, sig)
    if decision.outcome != "ALLOW":
        raise RuntimeError(
            f"Records delegation {task_id} failed: "
            f"{decision.outcome} | {decision.reason}"
        )

    world["ledger"].delegate_scope_only(
        task_id,
        a,
        b,
        "compile_medication_summary",
        "records_api",
        "read",
        {"patient": patient},
    )


def delegate_schedule(world, task_id, patient):
    a, c = world["a"], world["c"]

    req, sig = make_signed_request(
        a,
        "delegate_task",
        "scheduler_agent",
        "delegate",
        task_id=task_id,
        patient=patient,
    )
    decision = world["pep"].handle(req, sig)
    if decision.outcome != "ALLOW":
        raise RuntimeError(
            f"Schedule delegation {task_id} failed: "
            f"{decision.outcome} | {decision.reason}"
        )

    world["ledger"].delegate_scope_only(
        task_id,
        a,
        c,
        "book_followup",
        "calendar",
        "write",
        {"patient": patient},
    )


async def controlled_tool_call(
    client,
    *,
    world,
    case_id,
    agent,
    agent_label,
    task_type,
    resource,
    action,
    task_id,
    patient,
    mcp_tool,
    tool_args,
    expected_decision,
    expected_result,
):
    """Pass an agent request through the existing PEP before MCP invocation."""

    trust_before = world["trust"].score(agent.agent_id)

    request, signature = make_signed_request(
        agent,
        task_type,
        resource,
        action,
        task_id=task_id,
        patient=patient,
    )

    decision = world["pep"].handle(request, signature)

    before = INVOCATIONS[mcp_tool]
    invoked = False
    observed_result = f"{decision.outcome}: {decision.reason}"
    tool_text = ""

    # Critical enforcement rule:
    # protected MCP tool is invoked only after an ALLOW decision.
    if decision.outcome == "ALLOW":
        result = await client.call_tool(mcp_tool, tool_args)
        invoked = True
        tool_text = result.content[0].text
        observed_result = f"ALLOW; MCP tool executed"

    after = INVOCATIONS[mcp_tool]

    invocation_consistent = (
        (invoked and after == before + 1)
        or (not invoked and after == before)
    )

    passed = (
        decision.outcome == expected_decision
        and invocation_consistent
        and (
            (expected_decision == "ALLOW" and invoked)
            or (expected_decision != "ALLOW" and not invoked)
        )
    )

    row = {
        "case_id": case_id,
        "agent": agent_label,
        "mcp_tool": mcp_tool,
        "resource": resource,
        "action": action,
        "patient_id": patient,
        "trust_before": f"{trust_before:.2f}",
        "zero_trust_decision": decision.outcome,
        "decision_reason": decision.reason,
        "mcp_tool_invoked": str(invoked),
        "expected_result": expected_result,
        "observed_result": observed_result,
        "pass": str(passed),
    }

    return row, tool_text


async def main():
    rows = []

    async with Client(server, raise_exceptions=True) as client:
        protocol_version = str(client.protocol_version)

        # ---------------------------------------------------------------
        # MCP-01: assigned Records Agent reads its delegated patient.
        # ---------------------------------------------------------------
        world = build("V2")
        delegate_records(world, "MCP-T01", "SYN-0001")

        row, _ = await controlled_tool_call(
            client,
            world=world,
            case_id="MCP-01",
            agent=world["b"],
            agent_label="Agent B (records)",
            task_type="compile_medication_summary",
            resource="records_api",
            action="read",
            task_id="MCP-T01",
            patient="SYN-0001",
            mcp_tool="records_read",
            tool_args={"patient_id": "SYN-0001"},
            expected_decision="ALLOW",
            expected_result="Assigned patient read executes through MCP",
        )
        rows.append(row)

        # ---------------------------------------------------------------
        # MCP-02: same role but wrong patient under the delegated task.
        # ---------------------------------------------------------------
        world = build("V2")
        delegate_records(world, "MCP-T02", "SYN-0001")

        row, _ = await controlled_tool_call(
            client,
            world=world,
            case_id="MCP-02",
            agent=world["b"],
            agent_label="Agent B (records)",
            task_type="compile_medication_summary",
            resource="records_api",
            action="read",
            task_id="MCP-T02",
            patient="SYN-0002",
            mcp_tool="records_read",
            tool_args={"patient_id": "SYN-0002"},
            expected_decision="BLOCK",
            expected_result="Wrong-patient request blocked before MCP invocation",
        )
        rows.append(row)

        # ---------------------------------------------------------------
        # MCP-03: Scheduler performs its authorised Calendar write.
        # ---------------------------------------------------------------
        world = build("V2")
        delegate_schedule(world, "MCP-T03", "SYN-0001")

        row, _ = await controlled_tool_call(
            client,
            world=world,
            case_id="MCP-03",
            agent=world["c"],
            agent_label="Agent C (scheduler)",
            task_type="book_followup",
            resource="calendar",
            action="write",
            task_id="MCP-T03",
            patient="SYN-0001",
            mcp_tool="calendar_write",
            tool_args={
                "patient_id": "SYN-0001",
                "slot": "2026-08-25T10:00",
                "context": "authorised follow-up",
            },
            expected_decision="ALLOW",
            expected_result="Authorised Calendar write executes through MCP",
        )
        rows.append(row)

        # ---------------------------------------------------------------
        # MCP-04: Scheduler attempts a clinical-record write.
        # Policy should block before any MCP tool is called.
        # ---------------------------------------------------------------
        world = build("V2")
        delegate_schedule(world, "MCP-T04", "SYN-0001")

        row, _ = await controlled_tool_call(
            client,
            world=world,
            case_id="MCP-04",
            agent=world["c"],
            agent_label="Agent C (scheduler)",
            task_type="book_followup",
            resource="records_api",
            action="write",
            task_id="MCP-T04",
            patient="SYN-0001",
            mcp_tool="records_read",
            tool_args={"patient_id": "SYN-0001"},
            expected_decision="BLOCK",
            expected_result="Clinical-record write blocked before MCP invocation",
        )
        rows.append(row)

        # ---------------------------------------------------------------
        # MCP-05: quarantined Records Agent attempts protected access.
        # ---------------------------------------------------------------
        world = build("V2")
        delegate_records(world, "MCP-T05", "SYN-0001")
        world["trust"].set_score(world["b"].agent_id, 0.39)

        row, _ = await controlled_tool_call(
            client,
            world=world,
            case_id="MCP-05",
            agent=world["b"],
            agent_label="Agent B (records, quarantined)",
            task_type="compile_medication_summary",
            resource="records_api",
            action="read",
            task_id="MCP-T05",
            patient="SYN-0001",
            mcp_tool="records_read",
            tool_args={"patient_id": "SYN-0001"},
            expected_decision="BLOCK",
            expected_result="Quarantined agent blocked before MCP invocation",
        )
        rows.append(row)

        # ---------------------------------------------------------------
        # MCP-06: complete compliant discharge workflow.
        # B's MCP output becomes context for C's MCP tool call.
        # ---------------------------------------------------------------
        world = build("V2")

        delegate_records(world, "MCP-T06-R", "SYN-0003")
        records_row, records_output = await controlled_tool_call(
            client,
            world=world,
            case_id="MCP-06-R",
            agent=world["b"],
            agent_label="Agent B (records)",
            task_type="compile_medication_summary",
            resource="records_api",
            action="read",
            task_id="MCP-T06-R",
            patient="SYN-0003",
            mcp_tool="records_read",
            tool_args={"patient_id": "SYN-0003"},
            expected_decision="ALLOW",
            expected_result="Records step executes",
        )

        delegate_schedule(world, "MCP-T06-C", "SYN-0003")
        calendar_row, _ = await controlled_tool_call(
            client,
            world=world,
            case_id="MCP-06-C",
            agent=world["c"],
            agent_label="Agent C (scheduler)",
            task_type="book_followup",
            resource="calendar",
            action="write",
            task_id="MCP-T06-C",
            patient="SYN-0003",
            mcp_tool="calendar_write",
            tool_args={
                "patient_id": "SYN-0003",
                "slot": "2026-08-26T09:30",
                "context": records_output,
            },
            expected_decision="ALLOW",
            expected_result="Calendar step executes using prior agent output",
        )

        workflow_pass = (
            records_row["pass"] == "True"
            and calendar_row["pass"] == "True"
            and bool(records_output)
        )

        rows.append({
            "case_id": "MCP-06",
            "agent": "Agent B -> Agent C",
            "mcp_tool": "records_read -> calendar_write",
            "resource": "records_api -> calendar",
            "action": "read -> write",
            "patient_id": "SYN-0003",
            "trust_before": "B=0.70; C=0.70",
            "zero_trust_decision": (
                f"{records_row['zero_trust_decision']} -> "
                f"{calendar_row['zero_trust_decision']}"
            ),
            "decision_reason": (
                f"records: {records_row['decision_reason']}; "
                f"calendar: {calendar_row['decision_reason']}"
            ),
            "mcp_tool_invoked": str(
                records_row["mcp_tool_invoked"] == "True"
                and calendar_row["mcp_tool_invoked"] == "True"
            ),
            "expected_result": (
                "End-to-end discharge chain executes through both MCP tools"
            ),
            "observed_result": (
                "Agent B record output passed as context to Agent C Calendar call"
            ),
            "pass": str(workflow_pass),
        })

        # Keep only the six dissertation validation cases.
        # MCP-06-R and MCP-06-C are internal substeps represented by MCP-06.
        for row in rows:
            row["mcp_protocol_version"] = protocol_version

    fields = [
        "case_id",
        "agent",
        "mcp_tool",
        "resource",
        "action",
        "patient_id",
        "trust_before",
        "zero_trust_decision",
        "decision_reason",
        "mcp_tool_invoked",
        "expected_result",
        "observed_result",
        "pass",
        "mcp_protocol_version",
    ]

    with open(
        "results_mcp_zero_trust_pilot.csv",
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    labels = {
        "MCP-01": "Assigned records read",
        "MCP-02": "Wrong-patient records read",
        "MCP-03": "Authorised calendar write",
        "MCP-04": "Clinical-record write",
        "MCP-05": "Quarantined-agent request",
        "MCP-06": "End-to-end discharge workflow",
    }

    passed_count = sum(row["pass"] == "True" for row in rows)

    print("=" * 72)
    print("STUDY E — MCP ZERO TRUST INTEGRATION PILOT")
    print(f"MCP protocol version: {rows[0]['mcp_protocol_version']}")
    print("=" * 72)

    for row in rows:
        status = "PASS" if row["pass"] == "True" else "FAIL"
        decision = row["zero_trust_decision"]
        print(
            f"{row['case_id']:7} "
            f"{labels[row['case_id']]:34} "
            f"{decision:15} {status}"
        )

    print("-" * 72)
    print(f"{passed_count} / {len(rows)} validation cases passed")
    print("Structured evidence written to results_mcp_zero_trust_pilot.csv")
    print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())
