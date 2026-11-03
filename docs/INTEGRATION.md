# Integration checklist

Do not connect the demonstration directly to a real service. A safe evaluation begins with a tabletop or sandbox exercise around an existing, approved manual procedure.

1. Identify a non-safety-critical **record** that has an existing owner and reconciliation process.
2. Define which fields are authoritative, who issues grants, who authenticates operators and how witnesses are independently verified.
3. Establish a strict, human-readable scope: one incident, one action, literal site segments, a short expiry and low use limit.
4. Store signing keys outside the local device. Configure independently obtained public-key pins.
5. Run the gate in a segregated test environment. Log no personal or sensitive information.
6. Exercise denial, outage, device loss, duplicate record, revoked grant and reconnection cases.
7. Reconcile against a sandbox authoritative system. Decide in writing how uncertain or conflicting records are handled.
8. Only then consider an independently reviewed pilot under the service owner's governance.

For AffixIO integration, use only documented SDK evidence functions. Keep proof verification and actual business enforcement separate: proof success is a signal, not a licence to perform an action outside policy.
