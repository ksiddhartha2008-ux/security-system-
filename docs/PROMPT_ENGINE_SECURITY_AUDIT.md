# Prompt Engine security audit

Date: 9 November 2026
Conclusion: **there is no Prompt Engine, LLM client, agent framework or prompt template in this repository.** The audit therefore records the absence, verifies it, and defines the requirements for any future addition. It does not fabricate findings against code that does not exist.

## Evidence

| Check | Command | Result |
| --- | --- | --- |
| Dependencies | `rg -n "openai|langchain|langgraph|crewai|autogen|anthropic|prompt|llm|agent" backend/package.json frontend/package.json package.json` | No matches |
| Prompt code | `rg -l -i "prompt" backend/src frontend/src` | No files |
| Model calls | `rg -n "api.openai|anthropic|completion|chat" backend/src` | No matches |
| Server dependencies | `backend/package.json` | `express`, `zod` only |
| Web dependencies | `frontend/package.json` | `react`, `react-dom`, `react-router-dom`, `lucide-react` |
| Network egress | Source review of every `fetch` call | MiroFish adapter, VirusTotal, AbuseIPDB only; no model provider |

## What "AI Detection Center" actually means here

The module is deterministic:

1. Rules aggregate events over explicit windows (`backend/src/services/detection.js`).
2. A score is computed from base severity, capped factor weights, asset criticality and a confidence lift.
3. The factors, observed values and score model are stored with each detection and shown to the analyst.
4. The UI states: "Deterministic rules with stored scoring factors. AI does not decide here; every score can be traced."

There is no model inference, no prompt, no token accounting, no provider key, and no natural language generation. The word "AI" in the product name is positioning, not a runtime component.

## Security consequences

| Threat | Applicability | Notes |
| --- | --- | --- |
| Direct prompt injection | Not applicable | No prompts are constructed |
| Indirect prompt injection via events, URLs, logs, email | Not applicable today | Those inputs are parsed by deterministic code and SQL, not by a model |
| Jailbreak | Not applicable | No model |
| Tool misuse by an agent | Not applicable | No tool calling; the SOAR engine is rule configured and human approved |
| Cross-tenant context leakage through prompts | Not applicable | No prompt context |
| Hallucinated security findings | Not applicable to detections | Detection output is computed, not generated |
| AI-generated automation suggestions | Not applicable | Workflows are authored by admins |

If the project later adds a summarisation or triage model, the following become mandatory and are **not implemented now**:

1. A single prompt template module with versioned templates and explicit variables.
2. A trust boundary that labels every external string (event title, URL, log line, email body) as untrusted data, never as instructions.
3. Structured output only, validated against a schema, with a safe fallback when the model fails.
4. A server-side tool gateway: authentication, role, tenant ownership, schema, risk class, approval, audit.
5. Prompt and response logging with redaction, retention limits and no secrets.
6. A regression corpus covering direct and indirect injection, cross-tenant attempts, malformed JSON and unsafe action proposals.

## Existing controls that already fit that future pipeline

- **Human approval for destructive actions** is enforced server side (`workflow_executions`), independent of any model.
- **Tenant scoping** is applied from the session, so a future model cannot request another tenant's data by naming an id.
- **Audit hash chain** records who did what, with request correlation ids.
- **Deterministic detection** remains available if a model provider is down.

## Verdict

The Prompt Engine security sections of the remediation brief are **not applicable** to this build. Marking them "implemented" would be false. The correct status is: no engine exists; the deterministic path is audited; the architecture and requirements for a future engine are documented in `PROMPT_ENGINE_ARCHITECTURE.md`.
