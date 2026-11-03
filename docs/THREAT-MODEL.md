# Threat model

| Threat | Example response | Remaining limitation |
|---|---|---|
| Caller changes a site or action | Exact grant fields and literal scope checks | Host adapter must pass the same approved data onward |
| Caller claims a different operator | Authenticated operator separate from request data | Authentication is not implemented by this demo |
| Grant is copied or altered | Pinned issuer Ed25519 signature | Compromised issuer key remains a compromise |
| A local record is replayed | Durable unique operation ID and use counter | Separate sites need later reconciliation |
| Witness requirement is bypassed | Distinct witness identities required in data model | Real-world independence needs organisational controls |
| Local database is unavailable | Fail closed | Availability needs operational fallback, not a software workaround |
| Audit history is rewritten | Signed events plus external checkpoint | No immutable ledger or anti-rollback protection |
| Connectivity returns with changed policy | Reconciliation result may require recheck | No live policy integration exists |

The reference does not address stolen devices, compromised operating systems, time manipulation, key recovery, hardware attestation, denial of service, physical access, collusion, social engineering, cross-site conflict resolution or statutory compliance. These are deployment design questions, not omissions a README can solve.
