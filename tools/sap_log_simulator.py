#!/usr/bin/env python3
"""SAP Security Audit Log simulator.

Generates synthetic security-audit-log events in the normalised JSON schema used by
the Sigma rules in sigma/rules/sap/.

Every event_type below corresponds to an event class SAP documents as recordable in the
Security Audit Log (transaction SM19 / RSAU_CONFIG, read in SM20). Nothing here is real
system data: the generator is fully seeded and produces reproducible output.

Usage:
    python3 tools/sap_log_simulator.py --seed 42 --events 400 > sample_logs.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone

# Event classes SAP documents as recordable in the Security Audit Log.
EVENT_TYPES = [
    "logon_success",
    "logon_failure",
    "rfc_logon_success",
    "rfc_function_module_call",
    "transaction_start",
    "transaction_end",
    "report_start",
    "user_master_change",
    "role_change",
    "role_assignment",
    "audit_config_change",
    "http_session_mgmt_change",
    "file_download",
]

# Benign transaction codes a business user legitimately runs.
BUSINESS_TCODES = [
    "FB60", "VA01", "ME21N", "MIRO", "FB50", "FBV0", "PA30", "PC00",
    "ME21N", "VA02", "FB02", "CO01",
]

# Transactions an administrator legitimately runs.
ADMIN_TCODES = ["SM51", "SM21", "SM04", "ST03N", "SM12", "SM37", "SM50"]

# High risk transactions. SE16N is covered by a dedicated rule because it bypasses the
# role model; SE16 is its checked, gated sibling and is used here as the realistic
# fallback an analyst would see.
HIGH_RISK_TCODES = ["SE16N", "SU01", "PFCG", "SM59", "SE38", "SA38", "SE16"]

USERS_BUSINESS = [
    "J.DUPONT", "A.MARTIN", "C.PETIT", "L.MOREAU", "S.ROUX",
    "M.GARNIER", "N.BERNARD", "E.DURAND", "P.LEROY", "K.THOMAS",
]
USERS_ADMIN = ["BASIS_SVC", "SEC_ADMIN", "DBA_ONCALL"]

# A client host outside the corporate subnet: used only by planted attack scenarios.
HOST_INSIDE = "10.20.30.{}"
HOST_OUTSIDE = "203.0.113.{}"


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _base(ts: datetime, rng: random.Random) -> dict:
    return {
        "timestamp": _iso(ts),
        "sap_system": "PRD",
        "sap_instance": "00",
        "sap_client": "100",
        "event_type": "transaction_start",
        "user": rng.choice(USERS_BUSINESS),
        "client_host": HOST_INSIDE.format(rng.randint(2, 60)),
        "terminal": f"SAPGUI_0{rng.randint(1, 4)}",
        "tcode": None,
        "status": "SUCCESS",
        "rfc_dest": None,
        "rfc_function": None,
        "object_name": None,
    }


def _benign(ts: datetime, rng: random.Random) -> dict:
    """Normal daytime activity for a business or admin user."""
    ev = _base(ts, rng)
    roll = rng.random()

    if roll < 0.34:
        ev["event_type"] = "transaction_start"
        pool = BUSINESS_TCODES if rng.random() < 0.8 else ADMIN_TCODES
        if ev["user"] in USERS_ADMIN:
            pool = ADMIN_TCODES
        ev["tcode"] = rng.choice(pool)
    elif roll < 0.44:
        ev["event_type"] = "logon_success"
    elif roll < 0.49:
        ev["event_type"] = "logon_failure"
        ev["status"] = "FAIL"
    elif roll < 0.54:
        ev["event_type"] = "report_start"
        ev["tcode"] = rng.choice(BUSINESS_TCODES)
    elif roll < 0.60:
        ev["event_type"] = "transaction_end"
        ev["tcode"] = rng.choice(BUSINESS_TCODES)
    elif roll < 0.66:
        ev["event_type"] = "rfc_function_module_call"
        ev["rfc_dest"] = rng.choice(["FI_PROD", "MM_PROD", "BATCHPRD"])
        ev["rfc_function"] = rng.choice(["BAPI_BUSINESS_PARTNER_GET", "Z_BAPI_SYNC_GL"])
    elif roll < 0.70:
        ev["event_type"] = "role_change"
        ev["user"] = rng.choice(USERS_ADMIN)
        ev["object_name"] = rng.choice(["Z_SALES_APPROVER", "FI_ALL", "Z_MM_STOCK"])
    elif roll < 0.73:
        ev["event_type"] = "role_assignment"
        ev["user"] = rng.choice(USERS_ADMIN)
        ev["object_name"] = rng.choice(["Z_SALES_APPROVER", "Z_MM_STOCK"])
    elif roll < 0.755:
        ev["event_type"] = "user_master_change"
        ev["user"] = rng.choice(USERS_ADMIN)
        ev["object_name"] = rng.choice(USERS_BUSINESS)
    elif roll < 0.77:
        ev["event_type"] = "file_download"
        ev["object_name"] = rng.choice(["/download/report.pdf", "/download/hr_extract.xlsx"])
    elif roll < 0.79:
        ev["event_type"] = "http_session_mgmt_change"
    else:
        ev["event_type"] = "transaction_start"
        # Legitimate table access goes through SE16, which requires an authorisation
        # check. SE16N is reserved for the attack scenario below.
        ev["tcode"] = "SE16"

    return ev


def _scenarios(start: datetime, rng: random.Random) -> list[dict]:
    """One attack scenario per Sigma rule, so detection can be demonstrated end to end."""
    out: list[dict] = []

    # 1 - Direct table access via SE16N, from an external IP, late in the evening.
    ev = _base(start + timedelta(hours=21, minutes=14), rng)
    ev.update(
        event_type="transaction_start",
        user="J.DUPONT",
        client_host=HOST_OUTSIDE.format(77),
        tcode="SE16N",
    )
    out.append(ev)

    ev = _base(start + timedelta(hours=21, minutes=18), rng)
    ev.update(
        event_type="transaction_start",
        user="J.DUPONT",
        client_host=HOST_OUTSIDE.format(77),
        tcode="SE16N",
    )
    out.append(ev)

    # 2 - Privilege escalation: a privileged account is unlocked, then a role is built.
    ev = _base(start + timedelta(hours=21, minutes=31), rng)
    ev.update(
        event_type="user_master_change",
        user="SEC_ADMIN",
        client_host=HOST_OUTSIDE.format(77),
        object_name="BASIS_SVC",
    )
    out.append(ev)

    ev = _base(start + timedelta(hours=21, minutes=36), rng)
    ev.update(
        event_type="role_change",
        user="SEC_ADMIN",
        client_host=HOST_OUTSIDE.format(77),
        object_name="Z_ALL_FUNCTIONS",
    )
    out.append(ev)

    ev = _base(start + timedelta(hours=21, minutes=40), rng)
    ev.update(
        event_type="role_assignment",
        user="SEC_ADMIN",
        client_host=HOST_OUTSIDE.format(77),
        object_name="Z_ALL_FUNCTIONS",
    )
    out.append(ev)

    # 3 - The attacker reduces their own footprint: audit coverage is weakened.
    ev = _base(start + timedelta(hours=21, minutes=47), rng)
    ev.update(
        event_type="audit_config_change",
        user="SEC_ADMIN",
        client_host=HOST_OUTSIDE.format(77),
        object_name="SM19",
    )
    out.append(ev)

    ev = _base(start + timedelta(hours=21, minutes=52), rng)
    ev.update(
        event_type="transaction_start",
        user="SEC_ADMIN",
        client_host=HOST_OUTSIDE.format(77),
        tcode="SM18",
    )
    out.append(ev)

    # 4 - Remote privilege escalation over RFC to a second system.
    ev = _base(start + timedelta(hours=22, minutes=4), rng)
    ev.update(
        event_type="rfc_function_module_call",
        user="SEC_ADMIN",
        client_host=HOST_OUTSIDE.format(77),
        rfc_dest="BATCHPRD",
        rfc_function="SU01_USER_CREATE",
    )
    out.append(ev)

    # 5 - Password guessing against one account.
    for i in range(7):
        ev = _base(start + timedelta(hours=22, minutes=9 + i), rng)
        ev.update(
            event_type="logon_failure",
            status="FAIL",
            user="A.MARTIN",
            client_host=HOST_OUTSIDE.format(77),
        )
        out.append(ev)

    return out


def generate(seed: int, benign_events: int) -> list[dict]:
    rng = random.Random(seed)
    start = datetime(2026, 10, 9, 6, 0, 0, tzinfo=timezone.utc)

    events: list[dict] = []
    for i in range(benign_events):
        ts = start + timedelta(minutes=rng.randint(0, 900))
        events.append(_benign(ts, rng))

    events.extend(_scenarios(start, rng))
    events.sort(key=lambda e: e["timestamp"])
    return events


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=42, help="reproducibility seed")
    ap.add_argument(
        "--events",
        type=int,
        default=400,
        help="number of benign events to generate before the planted scenarios",
    )
    args = ap.parse_args(argv)

    for ev in generate(args.seed, args.events):
        print(json.dumps(ev, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())