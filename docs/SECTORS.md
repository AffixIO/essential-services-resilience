# Sector map: where a continuity evidence layer fits

The UK Government Resilience Framework names 13 Critical National Infrastructure sectors. This map is a planning aid, not a national service catalogue or operational guide.

| CNI sector | Potential evidence-layer use | Explicitly out of scope |
|---|---|---|
| Chemicals | Bounded maintenance handover or facility-access record | Process control, hazardous-material decisions |
| Civil nuclear | Administrative continuity-record evidence only | Plant controls, safety systems, security procedures |
| Communications | Restoration-team or site-access handover | Routing, broadcast or network configuration |
| Defence | Internal administrative workflow only, subject to owner approval | Operations, intelligence, weapons or classified systems |
| Emergency services | Logistics handover or supplies record | Dispatch, triage, incident command or 999 decisions |
| Energy | Maintenance attendance or documentation authority | Grid control, demand management or generation commands |
| Finance | Evidence around separately designed offline fallbacks | Settlement, accounts, credit, banking or regulated payment services |
| Food | Receipt of supplies or pre-approved distribution handover | Safety decisions, rationing policy or public eligibility decisions |
| Government | Continuity record with approved local policy | Statutory decisions or identity claims |
| Health | Non-clinical logistics and handover record | Diagnosis, treatment, prescribing, clinical priority or patient data |
| Space | Administrative maintenance record | Mission, satellite or launch control |
| Transport | Depot, access or maintenance handover record | Signalling, navigation, traffic control or passenger safety decisions |
| Water | Record of an already authorised manual continuity step | Pump, treatment, distribution or sewerage control |

## Design rule

Use this pattern only where a human-led, pre-defined procedure already exists and the extra problem is **proving who was allowed to create a limited record** while connectivity is unavailable. The system owner must decide whether that is appropriate. A computerised authorisation record must not create a shortcut around safety rules, statutory duties, local resilience arrangements or manual double-checks.

## Cross-sector elements

The pattern can be helpful for four cross-sector concerns:

1. **Pre-authorisation:** prepare constrained grants before disruption, rather than improvising authority during an incident.
2. **Witnessing:** require independent people for actions whose local procedure demands it.
3. **Offline accountability:** retain a bounded, signed record while central systems are unavailable.
4. **Reconnect-time reconciliation:** compare local records with current revocations, incident closure and host-system outcomes before accepting them as complete.

It cannot ensure availability, replace contingency stock, restore connectivity, resolve a conflicting record from another disconnected site, or make an action safe by itself.
