"""Data types deliberately limited to non-operational continuity records."""

import re
from dataclasses import asdict, dataclass, field

from .crypto import canonical, digest

SECTORS = frozenset(
    {
        "chemicals",
        "civil-nuclear",
        "communications",
        "defence",
        "emergency-services",
        "energy",
        "finance",
        "food",
        "government",
        "health",
        "space",
        "transport",
        "water",
    }
)


def identifier(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise ValueError("Invalid identifier")


def site(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value):
        raise ValueError("Site must use literal path segments")


def bounded_int(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 2**53 - 1:
        raise ValueError("Expected bounded integer")


def scoped(value, scope):
    return value == scope or value.startswith(scope + "/")


@dataclass(frozen=True)
class ContinuityGrant:
    grant_id: str
    incident_id: str
    sector: str
    action: str
    site_scope: str
    operator_id: str
    max_uses: int
    minimum_witnesses: int
    not_before: int
    expires_at: int
    audience: str = "resilience-site"

    def __post_init__(self):
        for value in (self.grant_id, self.incident_id, self.action, self.operator_id, self.audience):
            identifier(value)
        if self.sector not in SECTORS:
            raise ValueError("Unknown CNI sector")
        site(self.site_scope)
        bounded_int(self.max_uses, 1)
        bounded_int(self.minimum_witnesses, 0)
        bounded_int(self.not_before)
        bounded_int(self.expires_at)
        if self.expires_at <= self.not_before:
            raise ValueError("Invalid grant time window")

    def signed(self, authority):
        return authority.sign("continuity-grant", asdict(self))


@dataclass(frozen=True)
class ContinuityAction:
    operation_id: str
    incident_id: str
    sector: str
    action: str
    site: str
    operator_id: str
    witnesses: tuple[str, ...] = ()
    details: dict = field(default_factory=dict)
    audience: str = "resilience-site"

    def __post_init__(self):
        for value in (self.operation_id, self.incident_id, self.action, self.operator_id, self.audience):
            identifier(value)
        if self.sector not in SECTORS:
            raise ValueError("Unknown CNI sector")
        site(self.site)
        if type(self.witnesses) is not tuple:
            raise ValueError("Witnesses must be a tuple")
        if len(set(self.witnesses)) != len(self.witnesses) or self.operator_id in self.witnesses:
            raise ValueError("Witnesses must be distinct from operator")
        for witness in self.witnesses:
            identifier(witness)
        if type(self.details) is not dict:
            raise ValueError("Details must be an object")
        canonical({**asdict(self), "witnesses": list(self.witnesses)})

    @property
    def fingerprint(self):
        return digest({**asdict(self), "witnesses": list(self.witnesses)})


@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    receipt: dict


@dataclass(frozen=True)
class Reconciliation:
    status: str
    reason: str
