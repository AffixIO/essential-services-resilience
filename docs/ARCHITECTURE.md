# Architecture

## Trust roles

| Role | Owns | Must not be controlled by |
|---|---|---|
| Issuer | Signs constrained continuity grants | Agent, ordinary caller or local device user |
| Trusted site host | Authenticates operator and runs the local gate | Untrusted agent or request payload |
| Witness | Provides an independent presence required by local policy | The same principal as the operator |
| Audit signer | Signs chronological local records/checkpoints | The issuer where role separation is possible |
| Reconciler | Compares retained evidence with authoritative recovery state | Local disconnected record alone |

## Local decision sequence

```text
issuer-signed grant → trusted local identity → scope/time/revocation/witness checks
                  → atomic local reservation → signed audit record → later reconciliation
```

Each grant names one incident, sector, action, site boundary and operator, with a validity window and local-use limit. It has no wildcard action or site syntax. The gate uses SQLite `BEGIN IMMEDIATE` so parallel local requests cannot consume the same use limit twice.

The library records a decision and an operation reservation only. It intentionally has no callback or actuator. If an integrator introduces one, it must construct a separate safety case and ensure no protected action can bypass the decision boundary.

## Audit evidence

Audit events are Ed25519 signed and hash-linked. A separate signed checkpoint binds the expected event count and head. A verifier needs a pinned audit key, known ledger ID and checkpoint retained outside the untrusted export. This detects changes relative to that checkpoint, not a malicious administrator with control of all keys and storage.
