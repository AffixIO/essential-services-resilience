# Essential Services Resilience

**A simulation-only continuity-assurance toolkit for local, time-bounded records when normal connectivity is unavailable.**

During a severe outage, the difficult question is often not whether a person can take an action. It is whether the right person has authority for this exact, limited action, whether independent witnessing is required, and whether the decision can be reconciled safely when systems return.

This repository demonstrates that narrow boundary. It preserves **verifiable local authority, dual control, durable replay protection, revocation checks, tamper-evident records and later reconciliation**. It does not operate infrastructure.

> **Safety status:** research code. Every action and service in this repository is fictional. It contains no control-system connector, emergency-dispatch interface, payment rail, patient record, utility actuator, operational technology command or live API call.

## Why it exists

UK resilience planning recognises cascading disruption: loss of power can affect communications and other essential services. The UK Government lists 13 Critical National Infrastructure sectors. Continuity plans need people, processes, manual alternatives, rehearsals and accountable decisions. Software cannot replace any of those.

AffixIO can fit at one small point: evidence that a pre-approved, constrained local continuity record was authorised and later reconciled. [Scope and sector map](docs/SECTORS.md) makes clear where that is useful and where it is not.

## Five-minute local demo

Requires Python 3.10+.

```sh
git clone https://github.com/AffixIO/essential-services-resilience.git
cd essential-services-resilience
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[dev]'
python -m pytest -q
resilience-assurance
```

Expected outcome:

```text
Missing independent witness    REVIEW independent-witness-required
Fictional continuity record    ALLOW  continuity-record-authorised
Outside approved site          DENY   scope-mismatch
Audit: True | Reconciliation: RECONCILED
No physical system, service, payment, resident or emergency response was contacted.
```

The demo models a fictional water-site team recording an already-authorised backup operation. It never starts a pump, contacts a utility or controls any equipment.

## What the gate checks

```text
Pre-authorised continuity grant
  → signed issuer, incident, sector, site boundary, operator, expiry and use limit
  → local record proposes one action
  → trusted site supplies the authenticated operator
  → independent witnesses checked where policy requires them
  → SQLite reserves the operation before it is recorded
  → signed, hash-linked audit entry retained
  → after reconnection, retain and verify the checkpoint before reconciliation
```

| Result | Meaning | Any infrastructure action? |
|---|---|---|
| ALLOW | A fictional continuity record is inside its pre-authorised grant. | No. The library records only. |
| REVIEW | The record is in scope but needs the configured number of independent witnesses. | No. |
| DENY | Scope, identity, time, revocation, use or replay checks fail. | No. |

## Essential-service use cases the pattern can support

These are **recording and authorisation patterns**, not claims that AffixIO can deliver the service itself.

- Water: record a pre-approved, manually performed continuity procedure and dual-control witness.
- Health and emergency services: record logistics or handover authority, never diagnose, triage or dispatch.
- Food and fuel distribution: record bounded eligibility or stock handover, not a payment or rationing system.
- Communications and transport: record access, maintenance handover or restoration-work authority, not network or signalling control.
- Shelters, local authorities and voluntary-sector partners: record authorised supply release, access or distribution decisions without storing unnecessary personal data.
- Finance: add evidence around an existing, separately designed offline process. See the related [offline-payments simulation](https://github.com/AffixIO/offline-payments); it is not settlement.

The full sector-by-sector mapping is in [docs/SECTORS.md](docs/SECTORS.md). Read [safety boundaries](docs/SAFETY.md) before adapting anything.

## What this does not do

- It does not provide emergency instructions to the public.
- It does not determine life-safety priorities, prioritise patients, initiate emergency responses, or substitute responders' judgement.
- It does not control energy, water, telecoms, transport, medical devices, defence, chemicals, civil nuclear or space systems.
- It does not identify vulnerable people, track residents or process personal data in the demonstration.
- It does not create legal authority, regulatory compliance, final settlement, device trust or an immutable national ledger.
- It does not claim a relationship with, approval from, or integration into any UK public body or critical-infrastructure operator.

## Security model

An issuer signs a continuity grant. Each grant binds a single incident, sector, action name, literal site scope, operator, expiry, maximum local uses and witness requirement. The site gate independently pins issuer keys, checks revocation and serialises records in a durable local SQLite transaction. It signs audit events with a distinct audit key.

The library deliberately records hashes instead of raw `details`; this reduces routine disclosure but **is not anonymity**. Guessable inputs can be guessed from hashes. The trusted host, database, signer keys, clock and authentication context must remain outside the agent or caller's control.

See [architecture](docs/ARCHITECTURE.md), [threat model](docs/THREAT-MODEL.md), [research sources](docs/RESEARCH.md), and [integration checklist](docs/INTEGRATION.md).

## AffixIO boundary

This reference code uses local Ed25519 signatures to make the example runnable. It does **not** invent AffixIO SDK methods. A production adapter may attach AffixIO evidence using documented SDK interfaces, independently pinned signers and privacy-reviewed data minimisation. The decision boundary must remain in front of a protected business workflow, never after a real action.

## Development

```sh
python -m pip install -e '.[dev]'
python -m pytest -q
ruff check .
ruff format --check .
python -m build
```

The tests cover altered grants, unknown issuers, operator mismatch, witnesses, site boundaries, expiry, revocation, durable replay, use limits, concurrent attempts, local storage failure, audit tampering and reconciliation mismatch.

MIT licensed. See [SECURITY.md](SECURITY.md) for responsible reporting.
