# VEYLIX — Backend Integration Guide

Every route used by the UI is served by the Flask backend in the parent folder (`app.py`), and responses are
validated with the Zod schemas in `src/api/schemas.ts`, `src/api/files.ts` and `src/auth/auth.types.ts`. A response
that does not match is shown as "Unexpected backend response", never rendered as data.
Full route, role and error reference: [`../docs/API.md`](../docs/API.md). Pipeline design: [`../docs/EVENT_PIPELINE.md`](../docs/EVENT_PIPELINE.md).

## Configuration

| Variable | Purpose |
|---|---|
| `VITE_API_BASE_URL` | `/` or empty means same origin (recommended). `http(s)://host:port` means a separate backend (needs `CORS_ORIGINS` on the backend). Any other value shows "Backend URL misconfigured"; requests are never silently disabled. |
| `VITE_BACKEND_URL` | `npm run dev` only: proxy target for `/api` (default `http://127.0.0.1:5000`). The proxy also carries SSE and the session cookie. |
| `VITE_UI_PREVIEW` | Dev builds only: render layouts without a session. Compiled out of production. Keep `false`. |

See `.env.example`. `VITE_*` values are public (compiled into the bundle), so never put secrets in them.

## Auth and roles

`POST /api/v1/auth/login`, `GET /api/v1/auth/me` and `POST /api/v1/auth/logout` use an HttpOnly session cookie;
requests use `credentials: 'include'`.

| Role | Workspace | Notes |
|---|---|---|
| `EMPLOYEE` | `/employee/*` | File portal |
| `SECURITY_ANALYST` | `/soc/*` | Read and triage. The collector page is read-only. |
| `ADMIN` | `/soc/*` | Also gets collector controls (live, simulation, stop) and PCAP analysis (`canOperateCollector`) |

Client guards and disabled buttons are UX only. The backend enforces every role (403 is shown as "Permission denied").

## SOC views and their endpoints

| View | Endpoints |
|---|---|
| Security Overview | `GET /metrics`, `GET /health`, `GET /alerts?per_page=1000` |
| Alert Center / Incident | `GET /alerts`, `GET /alerts/{id}`, `PATCH /alerts/{id}` |
| Device | `GET /devices/{id}/timeline` |
| **Event Log** (`/soc/events`) | `GET /events?type=…&before_id=…&limit=50`, `GET /events/stats`, `GET /events/{uuid}` (detail, TLS metadata, correlations with method/confidence/rationale) |
| **Network Collector** (`/soc/collector`) | `GET /collector/status`, `GET /collector/interfaces`, `POST /collector/start` `{mode, interface, filter}`, `POST /collector/stop`, `POST /collector/pcap` (multipart; a 422 still carries partial counts), `GET /health` (detector state) |

Display rules:
- `data_source`/`source`: `live` → "Live capture"; `simulation` → "SIMULATED traffic", plus a banner on the collector page;
  `replay` → "Replayed data"; `pcap` → "Offline PCAP". Simulation is never shown as live.
- `detection_status`: `unavailable` is shown as "AI unavailable", `unsupported` as "Not model input",
  `not_applicable` as "Context only", and `failed` as "Scoring failed". A missing score is never shown as 0 or normal.
- Collector mode comes from the backend only. The Start buttons are disabled while running, while a request is
  pending, or when `live_capture_available` is false (the reason is displayed). The backend also rejects duplicates (`already_running`, 409 `busy`).

## Live updates (SSE) and polling

`src/api/live.ts` opens **one** `EventSource` to `GET /api/v1/stream/live` per tab. `SocShell` mounts it and
reference counting prevents duplicates under StrictMode or across views. Messages (`hello`, `event`, `alert`,
`correlation`, `collector_status`) only trigger React Query invalidation, batched every 750 ms. Collector status is
written directly from the stream. Views always re-read REST data, so a record seen by both SSE and polling cannot
be duplicated, and new-alert toasts are deduplicated by alert id. Reconnection uses backoff from 1 s up to 30 s.
Queries poll at their normal rate unless the stream is connected, when they slow down (`pollIntervalFor`). The
current state appears as a badge: "Live updates", "Reconnecting…" or "Polling".

## Employee file portal

`GET /files?folder_id=`, `POST /files` (multipart `file`, optional `folder_id`), `GET /files/{id}/download`,
`GET /files/activity`, `GET /employees/me`. Each operation also produces an `application_activity` security event
on the backend (it is not visible to the employee). File contents and names never reach the model.

## Tests

`npm test` (Vitest + jsdom + Testing Library):
- `src/api/client.test.ts`: base URL resolution, same-origin requests, error surfacing, FormData, login
- `src/api/live.test.ts`: single shared subscription, dedupe, backoff/reconnect, polling fallback, batched invalidation
- `src/features/soc/CollectorPage.test.tsx`: simulation labelling, analyst read-only, live start request, unavailable capture, backend outage, event log rendering
