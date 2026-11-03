from types import SimpleNamespace

import pytest

from resilience_assurance import ContinuityAction, ContinuityGate, ContinuityGrant, SigningKey


@pytest.fixture
def rig(tmp_path):
    issuer, auditor = SigningKey("issuer"), SigningKey("audit")
    now = [100]
    grant = ContinuityGrant(
        "grant",
        "incident",
        "water",
        "record_backup_operation",
        "sites/north",
        "operator",
        2,
        1,
        90,
        200,
        audience="site",
    )

    def new_gate():
        return ContinuityGate(
            tmp_path / "state.db",
            audience="site",
            issuer_pins={issuer.key_id: issuer.public_key},
            audit_signer=auditor,
            clock=lambda: now[0],
        )

    gate = new_gate()
    gate.add_grant(grant.signed(issuer))
    action = ContinuityAction(
        "op",
        "incident",
        "water",
        "record_backup_operation",
        "sites/north/a",
        "operator",
        witnesses=("witness",),
        details={"fictional": True},
        audience="site",
    )

    def record(value=None, target=None, grant_id="grant", actor="operator"):
        return (target or gate).record(value or action, grant_id, authenticated_operator=actor)

    return SimpleNamespace(**locals())
