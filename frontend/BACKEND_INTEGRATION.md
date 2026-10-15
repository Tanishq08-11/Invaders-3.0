# VEYLIX - Backend Integration Guide

> **Integration status: implemented.** Every route below is served by the Flask backend in the parent folder
> (`app.py`) and the live responses are validated against the Zod schemas in this folder. The frontend uses a
> same-origin API (`VITE_API_BASE_URL=/`): Flask serves `frontend/dist` in production and `npm run dev` proxies
> `/api` to `http://127.0.0.1:5000` (override with `VITE_BACKEND_URL`). See "Running the Full Stack" in the root
> README for demo accounts.
>
> Resolved decisions: alert status `open`/`dismissed` from the backend is mapped to `new`/`false_positive` in
> `schemas.ts` and accepted back on PATCH; the alert list is fetched with `?per_page=1000` and filtered
> client-side; accounts are seeded server-side (Engineering 15, Finance 10, HR 8, Sales & Marketing 12,
> Management 5, plus 2 analysts); each department has a shared folder, and personal files are private to their
> owner; per-user quota is 1 GiB and the request limit 100 MB. Per-alert `data_source` is not reported (the UI
> shows "Source not reported"); `metrics`/`health` report it from the collector/replay state.

Status legend: **AGREED** = in the team API spec. **PROPOSED** = defined by the frontend, needs Person 4's approval.
Every response shape below is **PROVISIONAL** until confirmed. Schemas live in
`src/api/schemas.ts`, `src/api/files.ts`, `src/auth/auth.types.ts` (Zod); change them there.

## Configuration
| Variable | Purpose |
|---|---|
| `VITE_API_BASE_URL` | Backend origin, no trailing slash. Empty => "awaiting backend connection". |
| `VITE_UI_PREVIEW` | Dev builds only. Renders layouts without a session. Compiled out of production. |

Requests use `credentials: 'include'`. The backend must set an **HttpOnly, Secure, SameSite** session cookie and
allow the frontend origin with credentials in CORS. No tokens or passwords are stored in the browser.

## Auth (PROPOSED)
| Route | Notes |
|---|---|
| `POST /api/v1/auth/login` | Body `{username, password}`. Sets session cookie. Returns user (or `{user}`). 401 on bad credentials. |
| `GET /api/v1/auth/me` | Current user; 401 when no session. |
| `POST /api/v1/auth/logout` | Clears session. |

User object: `{ id, username?, display_name, role: "EMPLOYEE"|"SECURITY_ANALYST", department?, email?, storage_used_bytes?, storage_quota_bytes? }`.
A 401 on any request while signed in shows the "session expired" state. Roles and permissions are enforced by
the backend on every request; client route guards are UX only.

**Account provisioning:** the backend must securely create the 50 employee accounts (proposed split: Engineering 15,
Finance 10, HR 8, Sales & Marketing 12, Management 5) with server-side password hashing. Nothing is seeded in the frontend.

## Employee files (PROPOSED)
| Route | Contract |
|---|---|
| `GET /api/v1/files?folder_id=` | `{items: FileItem[], path?: [{id,name}], permissions?: {view,upload,download}}` or a bare `FileItem[]`. |
| `POST /api/v1/files` | `multipart/form-data`: `file`, optional `folder_id`. 2xx only when stored. 403 no permission, 413 too large. |
| `GET /api/v1/files/{id}/download` | Authenticated binary stream. 403 / 404 distinct. |
| `GET /api/v1/files/activity` | `ActivityEntry[]` (or `{items}`): `{id, timestamp, action: upload|download|access|denied, file_name?, result: success|denied|failed, detail?}` |
| `GET /api/v1/employees/me` | Same shape as the user object above. |

`FileItem`: `{id, name, kind: file|folder, parent_id?, size_bytes?, mime_type?, uploaded_at?, owner?, permissions?: {view,upload,download}}`.
Missing `permissions` renders as "Permission unavailable". Upload size limit shown in the UI is 100 MB (`features/employee/shared.tsx`) - confirm the real limit.

Privacy: file contents, names and application activity must never be inputs to the anomaly model, and
analysts must not gain file-content access through the SOC.

## SOC (AGREED routes, PROVISIONAL shapes)
| Route | Frontend expects |
|---|---|
| `GET /api/v1/alerts` | `Alert[]` or `{items, total?}`. Filtering, sorting, search and pagination are done **client-side** today; send full list or agree on query params. |
| `GET /api/v1/alerts/{id}` | Alert + `explanation?`, `risk_contributions?[]`, `events?[]`, `metadata?`, `analyst_note?`, `model_version?`. |
| `GET /api/v1/devices/{id}/timeline` | `{device_id, data_source?, events?[], baseline?, unusual_destinations?[], bursts?[], related_alert_ids?[]}` |
| `GET /api/v1/metrics` | `{monitored_devices?, observed_events?, open_incidents?, high_priority_alerts?, severity_distribution?, traffic_trend?[{timestamp,bytes_out,events}], data_source?, generated_at?}` |
| `PATCH /api/v1/alerts/{id}` | Body `{status?: new|investigating|resolved|false_positive, note?}`. UI re-fetches the alert afterwards. |
| `GET /api/v1/health` | `{status, model_loaded?, model_version?, database?, ingestion?, last_event_at?, data_source?}` |
| `POST /api/v1/events` | Ingestion service only; never called by the UI. |

Alert: `{id, created_at (ISO UTC), device_id, source_ip?, destination?, destination_port?, bytes_out?, risk_score: number|null, scoring_status?: ok|failed, severity: critical|high|medium|low|info, status, signals: string[]|{code,label}[], data_source?: live|replay}`.

Rules the UI relies on:
- `risk_score` null / `scoring_status: "failed"` is shown as "unavailable"/"scoring failed", never as 0 or safe.
- `data_source` distinguishes **replayed** historical data from **live** capture; absent => "Source not reported".
- Device = identifier only; no employee identity is shown unless a verified mapping is added later.

SOC overview extras (all optional - the UI shows "not reported" when absent):
- `traffic_trend[].bytes_in` enables the inbound line; `anomalies` places anomaly markers on the trend.
- `alert.source_ip` and `alert.bytes_out` fill the Source and Outbound columns of the flagged-activity table.
- **Missing contract:** there is no raw flow-list endpoint (e.g. `GET /api/v1/flows`). The overview therefore shows *flagged* activity (alerts), not a live feed of all flows, and is not labelled "Live". If a streaming/polled flow endpoint is added, the table can be switched to it.
- Threat-analysis bars are computed in the browser as the share of received alerts whose reported `signals` match each category (volume, destination novelty, activity time, burst). They are prevalence counts, not probabilities and not model scores.

## Errors
Non-2xx: optionally `{detail}` or `{message}` (shown to the user). Invalid JSON/shape => "Unexpected backend response".

## Missing / to decide with Person 4
1. No device list endpoint (device count only via `metrics`).
2. Alert-list pagination/filter query params and sort fields.
3. Whether alert detail embeds events or needs a separate resource.
4. Baseline definition and window for device timeline.
5. Verified employee<->device mapping (needed before any identity is shown).
6. File size/type limits; CORS origins; session lifetime.

## Integration test steps
1. Set `VITE_API_BASE_URL`; the top bar should change from "Awaiting backend connection" to "Backend connected" once `/health` answers.
2. Log in as an employee: land on `/employee/dashboard`; verify profile, listing, upload (progress, 403, 413), download (403, 404).
3. Log in as an analyst: land on `/soc`; verify metrics, alerts, incident detail, device timeline, PATCH status update.
4. Verify an employee cannot open `/soc/*` and an analyst cannot open `/employee/*` (and that the backend itself returns 403).
5. Expire the session; the next request should show "session expired".
