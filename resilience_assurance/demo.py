"""Fictional, local continuity-record demonstration. No control systems are contacted."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from . import ContinuityAction, ContinuityGate, ContinuityGrant, SigningKey, verify_audit


def run_demo():
    issuer, auditor = SigningKey("resilience-authority"), SigningKey("local-audit")
    now = 1_800_000_000
    grant = ContinuityGrant(
        "water-continuity-01",
        "incident-2030-demo",
        "water",
        "record_backup_operation",
        "waterworks/north",
        "operator-alex",
        2,
        1,
        now - 60,
        now + 3600,
    )
    with TemporaryDirectory() as directory:
        gate = ContinuityGate(
            Path(directory) / "continuity.db",
            audience="resilience-site",
            issuer_pins={issuer.key_id: issuer.public_key},
            audit_signer=auditor,
            clock=lambda: now,
        )
        gate.add_grant(grant.signed(issuer))
        missing_witness = ContinuityAction(
            "water-001",
            "incident-2030-demo",
            "water",
            "record_backup_operation",
            "waterworks/north/pump-1",
            "operator-alex",
            details={"simulation": True, "note": "No equipment is operated"},
        )
        recorded = ContinuityAction(
            "water-002",
            "incident-2030-demo",
            "water",
            "record_backup_operation",
            "waterworks/north/pump-1",
            "operator-alex",
            witnesses=("witness-sam",),
            details={"simulation": True, "note": "No equipment is operated"},
        )
        wrong_site = ContinuityAction(
            "water-003",
            "incident-2030-demo",
            "water",
            "record_backup_operation",
            "waterworks/south/pump-1",
            "operator-alex",
            witnesses=("witness-sam",),
            details={"simulation": True},
        )
        decisions = [
            (
                "Missing independent witness",
                gate.record(missing_witness, grant.grant_id, authenticated_operator="operator-alex"),
            ),
            (
                "Fictional continuity record",
                gate.record(recorded, grant.grant_id, authenticated_operator="operator-alex"),
            ),
            (
                "Outside approved site",
                gate.record(wrong_site, grant.grant_id, authenticated_operator="operator-alex"),
            ),
        ]
        bundle = gate.export_audit()
        audit_valid = verify_audit(
            bundle,
            audit_pins={auditor.key_id: auditor.public_key},
            expected_ledger_id=gate.ledger_id,
            expected_checkpoint=bundle["checkpoint"],
        )
        reconciliation = gate.reconcile(bundle["checkpoint"], expected_checkpoint=bundle["checkpoint"])
        return {
            "mode": "simulation",
            "decisions": [
                {"scenario": name, "outcome": d.outcome, "reason": d.reason} for name, d in decisions
            ],
            "audit_valid": audit_valid,
            "reconciliation": reconciliation.status,
            "note": "No physical system, service, payment, resident or emergency response was contacted.",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    output = run_demo()
    if args.json:
        print(json.dumps(output, indent=2))
        return
    for decision in output["decisions"]:
        print(f"{decision['scenario']:<30} {decision['outcome']:<6} {decision['reason']}")
    print(f"Audit: {output['audit_valid']} | Reconciliation: {output['reconciliation']}")
    print(output["note"])


if __name__ == "__main__":
    main()
