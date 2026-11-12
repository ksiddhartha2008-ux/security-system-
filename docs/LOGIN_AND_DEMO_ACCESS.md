# Login and demo access

The sign-in screen was redesigned from the supplied reference images. The reference uses a browser-only demo session; this application keeps the real API session and server-side authorization.

## What the screen contains

- **Brand header**: SecureFlow AI and “Intelligent cybersecurity platform · MODULE 01”.
- **Demo authentication notice**: explains that the seeded account signs in through the real API and that a client-side role label never grants access.
- **Display name**: the seeded profile name, read-only. The server uses its own user record, so the field cannot be used to impersonate someone.
- **Email**: the seeded account address, read-only for the demo path.
- **Demo role segmented control**: Administrator, Security Analyst and Viewer. Selecting a role changes the seeded account, then **Continue to console** performs a normal login request.
- **SIMULATED footnote**: the demo dataset is synthetic and no customer credentials are involved.
- **Sign in with another account**: switches to the standard email and password form. This is the path for a real workspace account or a production deployment.
- **MFA**: if the selected account has TOTP enabled, the same six digit challenge used by the standard form appears after the password step.

## Role mapping

The reference images show five demo personas. This application has three real backend roles, so only those are offered:

| UI label | Backend role | Seeded account | Scope |
| --- | --- | --- | --- |
| Administrator | `admin` | Priya Raman, admin@secureflow.dev | Settings, People, destructive actions and every module |
| Security Analyst | `analyst` | Marcus Vale, analyst@secureflow.dev | Monitoring, triage, response and evidence |
| Viewer | `viewer` | Dana Okafor, viewer@secureflow.dev | Read-only |

Adding “Incident Responder” or “SOC Analyst” as separate buttons would be misleading because the backend would treat both as `analyst`. They were not added.

## Security behaviour

- The demo password comes from `/api/auth/demo-accounts`, which returns an empty list unless demo mode is on.
- `POST /api/auth/login` issues the session and CSRF token. The frontend never grants access from local state.
- The display name is not sent to the server. Editing it would have no effect, so the field is read-only.
- Demo accounts are not seeded in production. A production deployment uses the standard form with `SF_BOOTSTRAP_EMAIL` and `SF_BOOTSTRAP_PASSWORD`.
- The page has a single `main` landmark, one `h1`, labelled inputs and named buttons.

## Reference-inspired additions elsewhere

- Module eyebrow labels on every page: `MODULE 02` through `MODULE 16`, plus `SIMULATION LAB` and `DEMO TOOL`.
- Reports now opens with a **Posture snapshot** built from `/overview/summary`: events in 24 hours, critical/high events, open incidents and active detections with assets at risk.
- The application shell, badges, search fields and dashboard metric cards use Astryx as described in [ASTRYX_INTEGRATION.md](ASTRYX_INTEGRATION.md).

## Not adopted

- **Browser-only session.** It would bypass the backend, CSRF and role checks.
- **Editable display name and email as identity.** The server would ignore them, which would be a false affordance.
- **Five separate demo roles.** The backend has three.
- **Fabricated AI model inventory.** The reference’s “AI Detection Center” lists precision, recall and model versions. SecureFlow has deterministic rules and no model, so adding those numbers would be fabricated. The detection page reports real rule counts, risk scores and stored factors instead.
- **Report download sizes and PDF formats.** The reference table shows sizes and PDF files. The application exports real Markdown, CSV and JSON from generated reports; it does not display invented file sizes.
