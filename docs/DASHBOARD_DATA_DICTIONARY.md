# Dashboard data dictionary

Every value on the Overview page is a SQL aggregate over the caller's organization. There are no hardcoded numbers and no frontend-only series.

| Widget | Meaning | Source | Filter |
| --- | --- | --- | --- |
| Security events · 24h | Events in the last 24 hours | `security_events` | `org_id`, `occurred_at >= now-24h` |
| High severity events (foot) | High + critical events, all time | `security_events` | `severity IN ('high','critical')` |
| Open incidents | Incidents not resolved or closed | `incidents` | `status NOT IN ('resolved','closed')` |
| Critical incidents | Critical severity, still open | `incidents` | `severity='critical'`, open status |
| Incidents this week | Incidents detected in the last 7 days | `incidents` | `detected_at >= now-7d` |
| Open detections | Detections with status `open` | `detections` | `status='open'` |
| High risk detections | Open detections with risk ≥ 70 | `detections` | `status='open' AND risk_score>=70` |
| Assets at risk | Assets with risk ≥ 60 | `assets` | `risk_score >= 60` |
| Mean asset risk | Average asset risk | `assets` | AVG(`risk_score`) |
| Critical assets | Assets with critical criticality | `assets` | `criticality='critical'` |
| Event volume chart | Daily event count, high severity and detections | `security_events`, `detections` | 14 days, grouped by `substr(occurred_at,1,10)` |
| Severity mix donut | Event count per severity, 7 days | `security_events` | 7 days |
| Incidents needing a decision | Open incidents ordered by severity | `incidents` + `users` | open status, limit 5 |
| Asset risk ranking | Highest risk assets | `assets` | ordered by `risk_score DESC`, limit 5 |
| Recent telemetry | Newest events with asset hostname | `security_events` + `assets` | ordered by `occurred_at DESC`, limit 8 |
| Signal sources | Event count per source, 7 days | `security_events` | 7 days |
| Open vulnerabilities | Vulnerabilities not remediated | `vulnerabilities` | `status='open'` |
| Critical CVEs open | Critical vulnerabilities still open | `vulnerabilities` | `severity='critical' AND status='open'` |
| Mean time to resolve | Average hours between detection and resolution | `incidents` | last 25 resolved incidents |
| Simulations completed | Completed runs | `simulations` | `status='completed'` |
| Mean simulated risk | Average risk of scored runs | `simulations` | `risk_score IS NOT NULL` |

## Origin labels

`data_origin` is returned with events, assets, detections, incidents, vulnerabilities and network flows.

| Value | UI label | Counted in dashboard |
| --- | --- | --- |
| `REAL` | no badge (real telemetry) | Yes |
| `DEMO` | amber `demo` badge | Yes |
| `SIMULATED` | blue `simulated` badge | Yes |
| `TEST` | neutral `test` badge | Yes |

Dashboard totals include all origins because a SOC view should show everything. The badge on each record makes the origin explicit. The demo reset removes only `DEMO` rows, so counts drop accordingly while simulated and real records remain.

## Date handling

- All timestamps are stored as ISO 8601 UTC strings.
- Day buckets use `substr(occurred_at, 1, 10)`, which is the UTC date.
- The UI formats timestamps with `Intl.DateTimeFormat` in the viewer's locale.
- The 24 hour and 7 day windows are computed at query time, not cached.

## States

| State | Behaviour |
| --- | --- |
| Loading | Skeleton cards and table placeholders |
| Empty | Zero values with a useful explanation, never invented data |
| Error | Error card with retry, no stale values silently presented |
| Partial | Cards render independently; one failed query does not blank the page |

## Known limitations

- SQLite date arithmetic uses ISO string comparison; timestamps are always written by the server in that format.
- MTTR uses resolved incidents only; incidents without a resolution are excluded.
- The 14 day chart starts at zero for days without data.
- A new workspace shows zeros until telemetry is ingested or demo data is generated.
