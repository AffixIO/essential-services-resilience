"""Fail-closed continuity record gate. It never controls physical infrastructure."""

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict
from uuid import uuid4

from .crypto import canonical, digest, verify
from .models import ContinuityAction, ContinuityGrant, Decision, Reconciliation, scoped


class ContinuityUnavailable(RuntimeError):
    """When local continuity state cannot be safely checked, do not authorise a new record."""


class ContinuityGate:
    """Local record-and-decision boundary for pre-approved fictional outage actions."""

    def __init__(self, database, *, audience, issuer_pins, audit_signer, clock=None):
        self.database = str(database)
        if self.database == ":memory:" or not issuer_pins:
            raise ValueError("Use durable local storage and at least one independently pinned issuer")
        self.audience, self.issuer_pins, self.audit_signer = audience, dict(issuer_pins), audit_signer
        self.clock = clock or (lambda: int(time.time()))
        with self._transaction() as db:
            for statement in (
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, envelope TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS usage (id TEXT PRIMARY KEY, count INTEGER NOT NULL)",
                "CREATE TABLE IF NOT EXISTS revoked (id TEXT PRIMARY KEY)",
                "CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL)",
                "CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY, envelope TEXT NOT NULL)",
            ):
                db.execute(statement)
            identity = {
                "schema": "resilience.store.v1",
                "audience": audience,
                "audit_key_id": audit_signer.key_id,
                "audit_public_key": audit_signer.public_key,
            }
            row = db.execute("SELECT value FROM metadata WHERE key='identity'").fetchone()
            if row and json.loads(row[0]) != identity:
                raise ValueError("Database belongs to a different audience or audit key")
            db.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('identity', ?)", (canonical(identity).decode(),)
            )
            db.execute("INSERT OR IGNORE INTO metadata VALUES ('ledger_id', ?)", (str(uuid4()),))
            self.ledger_id = db.execute("SELECT value FROM metadata WHERE key='ledger_id'").fetchone()[0]

    @contextmanager
    def _transaction(self):
        database = None
        try:
            database = sqlite3.connect(self.database, timeout=10, isolation_level=None)
            database.execute("PRAGMA synchronous=FULL")
            database.execute("BEGIN IMMEDIATE")
            yield database
            database.commit()
        except sqlite3.Error as exc:
            if database:
                database.rollback()
            raise ContinuityUnavailable("Continuity state unavailable; no action was authorised") from exc
        except BaseException:
            if database:
                database.rollback()
            raise
        finally:
            if database:
                database.close()

    def _event(self, db, kind, details):
        previous = db.execute("SELECT sequence,envelope FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        sequence = previous[0] + 1 if previous else 1
        payload = {
            "ledger_id": self.ledger_id,
            "sequence": sequence,
            "at": self.clock(),
            "kind": kind,
            "details": details,
            "previous": digest(json.loads(previous[1])) if previous else "GENESIS",
        }
        envelope = self.audit_signer.sign("continuity-audit", payload)
        db.execute("INSERT INTO audit VALUES (?, ?)", (sequence, canonical(envelope).decode()))
        return envelope

    def add_grant(self, signed_grant):
        grant = ContinuityGrant(**verify(signed_grant, self.issuer_pins, "continuity-grant"))
        if grant.audience != self.audience:
            raise ValueError("Wrong grant audience")
        with self._transaction() as db:
            existing = db.execute("SELECT envelope FROM grants WHERE id=?", (grant.grant_id,)).fetchone()
            if existing:
                if json.loads(existing[0]) != signed_grant:
                    raise ValueError("Grant identifiers are immutable")
                return
            db.execute("INSERT INTO grants VALUES (?, ?)", (grant.grant_id, canonical(signed_grant).decode()))
            db.execute("INSERT INTO usage VALUES (?, 0)", (grant.grant_id,))
            self._event(db, "grant-added", {"grant_digest": digest(asdict(grant))})

    def revoke(self, grant_id):
        """Trusted administration; revocation is checked again at the local decision point."""
        with self._transaction() as db:
            db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (grant_id,))
            self._event(db, "grant-revoked", {"grant_id_digest": digest(grant_id)})

    def _evaluate(self, db, action, grant_id, authenticated_operator):
        if action.operator_id != authenticated_operator:
            return "DENY", "authenticated-operator-mismatch", None
        if action.audience != self.audience:
            return "DENY", "wrong-audience", None
        row = db.execute("SELECT envelope FROM grants WHERE id=?", (grant_id,)).fetchone()
        if not row:
            return "DENY", "unknown-grant", None
        if db.execute("SELECT 1 FROM revoked WHERE id=?", (grant_id,)).fetchone():
            return "DENY", "revoked", None
        try:
            grant = ContinuityGrant(**verify(json.loads(row[0]), self.issuer_pins, "continuity-grant"))
        except ValueError:
            return "DENY", "invalid-grant-signature", None
        now = self.clock()
        if not grant.not_before <= now < grant.expires_at:
            return "DENY", "expired-or-not-yet-valid", grant
        if (
            action.incident_id != grant.incident_id
            or action.sector != grant.sector
            or action.action != grant.action
            or action.operator_id != grant.operator_id
            or not scoped(action.site, grant.site_scope)
        ):
            return "DENY", "scope-mismatch", grant
        if len(action.witnesses) < grant.minimum_witnesses:
            return "REVIEW", "independent-witness-required", grant
        if db.execute("SELECT 1 FROM operations WHERE id=?", (action.operation_id,)).fetchone():
            return "DENY", "replay", grant
        used = db.execute("SELECT count FROM usage WHERE id=?", (grant_id,)).fetchone()[0]
        if used >= grant.max_uses:
            return "DENY", "grant-use-limit", grant
        return "ALLOW", "continuity-record-authorised", grant

    def decide(self, action, grant_id, *, authenticated_operator, reserve=False):
        copied = json.loads(canonical({**asdict(action), "witnesses": list(action.witnesses)}))
        copied["witnesses"] = tuple(copied["witnesses"])
        action = ContinuityAction(**copied)
        with self._transaction() as db:
            outcome, reason, grant = self._evaluate(db, action, grant_id, authenticated_operator)
            if outcome == "ALLOW" and reserve:
                db.execute(
                    "INSERT INTO operations VALUES (?, ?, 'RECORDED')",
                    (action.operation_id, action.fingerprint),
                )
                db.execute("UPDATE usage SET count=count+1 WHERE id=?", (grant_id,))
            receipt = self._event(
                db,
                "decision",
                {
                    "operation_id": action.operation_id,
                    "action_digest": action.fingerprint,
                    "grant_digest": digest(asdict(grant)) if grant else None,
                    "outcome": outcome,
                    "reason": reason,
                    "reserved": bool(reserve and outcome == "ALLOW"),
                },
            )
            return Decision(outcome, reason, receipt)

    def record(self, action, grant_id, *, authenticated_operator):
        """Record only. This method has no actuator, network client or control-system integration."""
        return self.decide(action, grant_id, authenticated_operator=authenticated_operator, reserve=True)

    def export_audit(self):
        with self._transaction() as db:
            events = [
                json.loads(row[0]) for row in db.execute("SELECT envelope FROM audit ORDER BY sequence")
            ]
            checkpoint = self.audit_signer.sign(
                "continuity-checkpoint",
                {
                    "ledger_id": self.ledger_id,
                    "count": len(events),
                    "head": digest(events[-1]) if events else "GENESIS",
                    "at": self.clock(),
                },
            )
            return {"schema": "affixio.resilience.audit.v1", "events": events, "checkpoint": checkpoint}

    def reconcile(self, receipt, *, expected_checkpoint, newly_revoked_grants=()):
        """A local simulation of reconnect-time review; it sends nothing and changes no external system."""
        for grant_id in newly_revoked_grants:
            self.revoke(grant_id)
        if receipt != expected_checkpoint:
            return Reconciliation("RECHECK", "checkpoint-mismatch")
        try:
            checkpoint = verify(
                receipt, {self.audit_signer.key_id: self.audit_signer.public_key}, "continuity-checkpoint"
            )
        except ValueError:
            return Reconciliation("RECHECK", "untrusted-checkpoint")
        return Reconciliation("RECONCILED", f"{checkpoint['count']}-event-local-ledger")


def verify_audit(bundle, *, audit_pins, expected_ledger_id, expected_checkpoint):
    """Verify event signatures and sequence against a separately retained checkpoint."""
    try:
        checkpoint = verify(expected_checkpoint, audit_pins, "continuity-checkpoint")
        if bundle["schema"] != "affixio.resilience.audit.v1" or bundle["checkpoint"] != expected_checkpoint:
            return False
        if checkpoint["ledger_id"] != expected_ledger_id or checkpoint["count"] != len(bundle["events"]):
            return False
        previous = "GENESIS"
        for sequence, event in enumerate(bundle["events"], 1):
            payload = verify(event, audit_pins, "continuity-audit")
            if payload["sequence"] != sequence or payload["ledger_id"] != expected_ledger_id:
                return False
            if payload["previous"] != previous:
                return False
            previous = digest(event)
        return previous == checkpoint["head"]
    except (KeyError, TypeError, ValueError):
        return False
