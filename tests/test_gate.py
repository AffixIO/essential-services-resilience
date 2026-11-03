import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace

import pytest

from resilience_assurance import (
    ContinuityAction,
    ContinuityGrant,
    ContinuityUnavailable,
    SigningKey,
    verify_audit,
)
from resilience_assurance.crypto import canonical
from resilience_assurance.demo import run_demo


def test_valid_fictional_continuity_record_is_authorised(rig):
    result = rig.record()
    assert (result.outcome, result.reason) == ("ALLOW", "continuity-record-authorised")


def test_missing_witness_requires_review_and_does_not_consume_grant(rig):
    no_witness = replace(rig.action, witnesses=())
    assert rig.record(no_witness).outcome == "REVIEW"
    assert rig.record().outcome == "ALLOW"


@pytest.mark.parametrize(
    "change",
    [
        {"incident_id": "other"},
        {"sector": "food"},
        {"action": "other"},
        {"site": "sites/south/a"},
        {"operator_id": "other"},
        {"audience": "other"},
    ],
)
def test_all_grant_scope_fields_are_enforced(rig, change):
    assert rig.record(replace(rig.action, **change)).outcome == "DENY"


def test_authenticated_operator_is_not_trusted_from_action(rig):
    assert rig.record(actor="impostor").reason == "authenticated-operator-mismatch"


def test_replay_is_durable_across_restart(rig):
    assert rig.record().outcome == "ALLOW"
    assert rig.record(target=rig.new_gate()).reason == "replay"


def test_use_limit_is_persistent(rig):
    assert rig.record().outcome == "ALLOW"
    assert rig.record(replace(rig.action, operation_id="op-2")).outcome == "ALLOW"
    assert rig.record(replace(rig.action, operation_id="op-3")).reason == "grant-use-limit"


def test_expiry_and_not_before_are_enforced(rig):
    rig.now[0] = 89
    assert rig.record().reason == "expired-or-not-yet-valid"
    rig.now[0] = 200
    assert rig.record().reason == "expired-or-not-yet-valid"


def test_revocation_blocks_new_offline_records(rig):
    rig.gate.revoke("grant")
    assert rig.record().reason == "revoked"


def test_altered_signed_grant_is_rejected(rig):
    forged = rig.grant.signed(rig.issuer)
    forged["payload"]["site_scope"] = "sites"
    with pytest.raises(ValueError):
        rig.gate.add_grant(forged)


def test_unknown_issuer_is_rejected(rig):
    stranger = SigningKey("other")
    with pytest.raises(ValueError):
        rig.gate.add_grant(replace(rig.grant, grant_id="other").signed(stranger))


def test_immutable_grant_id_cannot_be_rewritten(rig):
    with pytest.raises(ValueError):
        rig.gate.add_grant(replace(rig.grant, max_uses=99).signed(rig.issuer))


def test_literal_site_segments_prevent_prefix_confusion(rig):
    assert rig.record(replace(rig.action, site="sites/northern/a")).reason == "scope-mismatch"
    with pytest.raises(ValueError):
        replace(rig.action, site="sites/north/../south")


def test_witness_rules_reject_duplicates_and_operator_reuse(rig):
    with pytest.raises(ValueError):
        replace(rig.action, witnesses=("witness", "witness"))
    with pytest.raises(ValueError):
        replace(rig.action, witnesses=("operator",))


def test_parallel_workers_cannot_overconsume(rig):
    actions = [replace(rig.action, operation_id=f"op-{index}") for index in range(10)]
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(rig.record, actions))
    assert sum(result.outcome == "ALLOW" for result in results) == 2


def test_storage_failure_fails_closed(rig):
    with sqlite3.connect(rig.gate.database) as database:
        database.execute("DROP TABLE operations")
    with pytest.raises(ContinuityUnavailable):
        rig.record()


def test_audit_detects_tampering_reorder_and_truncation(rig):
    rig.record()
    bundle = rig.gate.export_audit()
    pins = {"audit": rig.auditor.public_key}
    check = lambda candidate: verify_audit(
        candidate,
        audit_pins=pins,
        expected_ledger_id=rig.gate.ledger_id,
        expected_checkpoint=bundle["checkpoint"],
    )
    assert check(bundle)
    changed = deepcopy(bundle)
    changed["events"][-1]["payload"]["details"]["outcome"] = "DENY"
    assert not check(changed)
    assert not check({**bundle, "events": bundle["events"][:-1]})
    assert not check({**bundle, "events": list(reversed(bundle["events"]))})


def test_details_do_not_appear_in_export(rig):
    secret = "fictional-sensitive-detail"
    rig.record(replace(rig.action, details={"note": secret}))
    assert secret not in str(rig.gate.export_audit())


def test_reconciliation_requires_expected_checkpoint(rig):
    bundle = rig.gate.export_audit()
    assert (
        rig.gate.reconcile(bundle["checkpoint"], expected_checkpoint=bundle["checkpoint"]).status
        == "RECONCILED"
    )
    assert rig.gate.reconcile({}, expected_checkpoint=bundle["checkpoint"]).status == "RECHECK"


def test_demo_never_calls_external_services():
    report = run_demo()
    assert report["mode"] == "simulation"
    assert report["audit_valid"] is True
    assert {item["outcome"] for item in report["decisions"]} == {"ALLOW", "DENY", "REVIEW"}


def test_float_details_and_action_values_are_rejected():
    with pytest.raises(ValueError):
        ContinuityAction(
            "op",
            "incident",
            "water",
            "record_backup_operation",
            "sites/north/a",
            "operator",
            details={"measurement": 1.5},
        )
    with pytest.raises(ValueError):
        ContinuityGrant("g", "i", "water", "record_backup_operation", "sites/north", "op", True, 1, 1, 2)


def test_canonical_omits_no_details_or_values():
    with pytest.raises(ValueError):
        canonical({"unexpected": object()})
