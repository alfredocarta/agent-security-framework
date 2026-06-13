#!/usr/bin/env python3
import argparse
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "asf_local.db")
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def _truncate(text: str, limit: int = 120) -> str:
    text = "" if text is None else str(text).replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print recent audit_trail events for one agent."
    )
    parser.add_argument("agent_id")
    parser.add_argument("--n", type=int, default=10)
    args = parser.parse_args()

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT timestamp, outcome, action, reason
            FROM audit_trail
            WHERE agent_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (args.agent_id, args.n),
        ).fetchall()

    if not rows:
        print(f"No audit events found for agent_id={args.agent_id}")
        return 0

    for timestamp, outcome, action, reason in rows:
        line = f"{timestamp} | {outcome} | {action} | {_truncate(reason)}"
        if outcome == "KILL_SWITCH":
            line = f"{RED}{line}{RESET}"
        elif outcome == "HITL_REQUESTED":
            line = f"{YELLOW}{line}{RESET}"
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
