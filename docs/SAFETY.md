# Safety boundaries

## This is not emergency response software

The code is not suitable for controlling physical systems or making emergency, clinical, safety, public-order, welfare, infrastructure, financial or eligibility decisions. It must not be connected to industrial control systems, medical systems, dispatch systems, production payment endpoints, personal data stores or public alerting services.

It never calls an external service. The only mutable state in the reference is a local SQLite database containing fictional identifiers and hashes.

## Do not use it to bypass procedure

Authority in the example is pre-issued, scoped and expiring. That does not substitute for an organisation's emergency plans, delegated authorities, segregation of duties, legal duties, local resilience arrangements, safeguarding controls or incident command. A `REVIEW` response must be handled through the organisation's existing trusted process; it is not an instruction to seek a workaround.

## Information minimisation

Do not enter names, addresses, patient information, account information, incident narratives or sensitive site details into `details`. The export omits raw details, but the production database still needs its own retention and protection plan. Hashes can reveal low-entropy information and should not be mistaken for encryption or anonymisation.

## Operational reality

Offline records are not globally final. Separate disconnected sites can make independently valid local records. On reconnection, a service owner must reconcile them against authoritative state and decide what happened. Never automatically treat an offline record as completed in an external system.

Before any trial, obtain approval from the relevant service owner, continuity lead, information-security team, legal/compliance functions and safety authority. Use a non-production exercise first, independent review, tested recovery, managed keys, access controls and written rollback/reconciliation procedures.
