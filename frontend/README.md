# VEYLIX Frontend

> **See the Threat. Never the Data.**

Frontend for VEYLIX, a prototype that detects potential data exfiltration by analysing encrypted-traffic **metadata** (never payloads). It contains:

- a public **landing page** and **login**
- an **Employee Portal** (`/employee/*`) - corporate file management
- a **Security Operations Center** (`/soc/*`) - alerts, incident details, device investigation

The app ships with **no application data**. Every screen is driven by typed backend responses and shows an honest
"awaiting backend connection" state until `VITE_API_BASE_URL` points at a running backend.

## Tech stack

React 19 · TypeScript · Vite · Tailwind CSS v4 · shadcn/ui (base-ui) · React Bits · Motion · Recharts ·
TanStack Query & Table · React Router · Zod · Sonner

## Getting started

Requires Node.js 20+.

```bash
npm install
cp .env.example .env     # then edit
npm run dev              # http://localhost:5173
```

| Script | Purpose |
|---|---|
| `npm run dev` | Start the dev server |
| `npm run build` | Type-check and production build |
| `npm run typecheck` | TypeScript only |
| `npm run lint` | oxlint |
| `npm run preview` | Serve the production build |

## Configuration

| Variable | Description |
|---|---|
| `VITE_API_BASE_URL` | Backend origin without trailing slash. Empty = disconnected states everywhere. |
| `VITE_UI_PREVIEW` | `true` renders layouts without a session. **Dev builds only**; ignored in production. |

## Project layout

```
src/
  app/          router
  api/          client, endpoints, TanStack Query hooks, Zod schemas (provisional contracts)
  auth/         AuthProvider, auth service, route guards
  components/   layout shells, common UI, charts, effects, shadcn/ui, React Bits
  features/     auth, landing, employee, soc
  lib/          formatting, routes, severity helpers
  types/        shared types inferred from schemas
```

## Backend integration

All API contracts are provisional until confirmed with the backend team. See
[BACKEND_INTEGRATION.md](BACKEND_INTEGRATION.md) for endpoints, schemas, session handling and test steps.

## Security notes

- Authentication, authorization and file permissions are enforced by the backend. Client route guards are UX only.
- No tokens or passwords are stored in the browser; sessions are expected to use an HttpOnly cookie.
- Alerts are indicators of anomalous behaviour, not proof of data theft.
