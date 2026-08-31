"""
m5_demo.py  --  Milestone M5: dynamic trust. An agent earns, and loses, authority.

Two short stories, each printed as a trust trajectory:

  Story 1  A scheduler that made an early mistake sits at 0.55, below the
           0.70 write tier, so its bookings are FLAGGED. It then completes
           verified tasks, climbs back past 0.70, and its writes succeed
           again. Trust is recovered by good behaviour.

  Story 2  A records agent is compromised and repeatedly returns fabricated
           summaries. Each verified violation multiplies its score by 0.7.
           After a few violations it falls below 0.40 and is QUARANTINED:
           every further request is blocked regardless of content.

Run with:  python m5_demo.py
"""

from trust import TrustStore, QUARANTINE, WRITE_TIER


def bar(score: float) -> str:
    filled = int(round(score * 20))
    tier = ("WRITE-OK" if score >= WRITE_TIER
            else "QUARANTINE" if score < QUARANTINE else "reads-only")
    return f"[{'#'*filled}{'.'*(20-filled)}] {score:0.2f}  {tier}"


def main():
    print("=" * 68)
    print("M5  Dynamic trust: earning and losing authority")
    print("=" * 68)

    trust = TrustStore()
    scheduler = "scheduler-C"
    records = "records-B"

    # ---- Story 1: recovering the write tier after a mistake -------------
    print("\nStory 1: a scheduler recovers the right to write")
    trust.set_score(scheduler, 0.55)                # an earlier flagged event
    print(f"   after a mistake  {bar(trust.score(scheduler))}  <- below 0.70: bookings FLAGGED")
    for i in range(1, 10):
        trust.reward(scheduler)                     # +0.02 per verified task
        crossed = trust.score(scheduler) >= WRITE_TIER and trust.score(scheduler) - 0.02 < WRITE_TIER
        note = "  <- back above 0.70: writes succeed again" if crossed else ""
        if i in (1, 5, 8, 9) or note:
            print(f"   after {i:2d} verified {bar(trust.score(scheduler))}{note}")

    # ---- Story 2: talking itself into quarantine ------------------------
    print("\nStory 2: a compromised records agent loses authority")
    print(f"   start            {bar(trust.score(records))}")
    step = 0
    while not trust.is_quarantined(records):
        step += 1
        trust.penalise_violation(records)           # x0.5 per verified violation
        flag = "  <- QUARANTINED: all requests now blocked" if trust.is_quarantined(records) else ""
        print(f"   violation {step:2d}     {bar(trust.score(records))}{flag}")

    ttq = trust.time_to_quarantine(records)
    print(f"\n   time-to-quarantine = {ttq} interactions "
          f"(first violation to below {QUARANTINE:.2f})")
    print("   this is the last metric in Table 3.5, now measurable.")


if __name__ == "__main__":
    main()
