# Phase report W3: detection and incidents

Date: 2026-11-11 UTC. Commit: `7d58cd1`, `60e02c8`.

## Delivered

- Nine website rules in `backend/src/services/websiteRules.js`, merged into the existing detection engine and rule table.
- `incident_entities` and `incident_detections` for entity based grouping and race safe attachment.
- `backend/src/services/websiteIncidents.js`: entity intersection, severity and priority escalation, timeline entries, throttled in-app notifications.
- Health signals: silent SDK, private client addresses, host mismatch.

## Evidence

- [W3.1](../verification/W3.1.md): 93 benign and 77 attack events, precision 1.000, recall 1.000, one incident.
- [W3.2](../verification/W3.2.md): grouped incident, P2, suppression with a reason.

## Issues found and fixed

- Incident titles kept the first rule after a more severe detection joined. Now the title follows the highest severity rule.
- A test waited for a detection count that would never occur and spent eight seconds. Corrected.

## Not delivered

- Tuning against real traffic. Thresholds remain starting values.
- Email or chat delivery.
