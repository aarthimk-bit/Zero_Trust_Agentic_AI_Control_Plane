"""
logger.py  --  Append-only behaviour log (the behaviour logger in Chapter 3).

Every identity check is recorded with its outcome. The log is append-only:
events are added to the end of events.log and never edited, which is what
makes it usable as an audit trail. In later milestones the same log records
policy decisions, task evidence checks, and trust updates, and it feeds the
evaluation metrics in Chapter 5.

M4 change (one line, backward compatible): large experiment runs set
logger.ECHO = False to silence the on-screen echo of each event, because a
200-task run produces hundreds of lines. The FILE, which is the actual
audit trail, is completely unchanged. The M1 to M3 demos behave exactly as
before, since ECHO defaults to True.
"""

from datetime import datetime, timezone

LOG_FILE = "events.log"
ECHO = True


def log_event(event_type: str, agent_id: str, outcome: str, detail: str) -> None:
    """Append one event line: timestamp | event | agent | outcome | detail."""
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    line = f"{timestamp} | {event_type} | agent={agent_id} | {outcome} | {detail}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    if ECHO:
        print("   log:", line.strip())
