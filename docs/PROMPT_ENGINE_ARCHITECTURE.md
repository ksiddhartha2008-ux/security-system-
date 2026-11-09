# Prompt and agent architecture

This document describes the target architecture **if** an LLM or agent capability is added, and maps it to what exists today. Nothing in the "target" column is implemented as a model pipeline; the current product is deterministic.

## Today

```
security event / URL / evidence metadata
        |
        v
validation (Zod)  ->  tenant scoping (session org id)
        |
        v
deterministic rule engine (SQL aggregation, fixed windows)
        |
        v
risk score + stored factors
        |
        v
analyst decision  ->  incident / investigation / SOAR workflow
        |
        v
SOAR approval gate (destructive actions always require approval)
        |
        v
recorded execution (simulated unless an integration is configured)
        |
        v
audit hash chain + request id
```

No prompt template layer, model router, model provider, context window, memory store, embedding index or agent tool exists.

## Target pipeline for a future AI feature

```
PROMPT TEMPLATE LAYER            versioned templates, explicit variables, no string concatenation of raw input
        |
INPUT VALIDATION LAYER           schema validation, length limits, tenant ownership checks
        |
CONTEXT AND TENANT ISOLATION     context assembled from the caller's org only; never from client supplied ids
        |
TRUST BOUNDARY                   untrusted content wrapped and labelled as data; instructions only from the template
        |
MODEL ROUTING LAYER              provider selection, timeout, retry cap, cost ceiling
        |
MODEL / AGENT FRAMEWORK          only if a real need is proven; no framework is installed today
        |
STRUCTURED OUTPUT VALIDATION     JSON schema, type and range checks, reject and fall back on failure
        |
TOOL AUTHORIZATION GATEWAY       auth, role, tenant, schema, risk class, approval, policy, audit
        |
RISK CLASSIFICATION              read-only vs destructive; destructive requires human approval
        |
CONTROLLED EXECUTION             server side only; no model-generated shell, SQL or HTTP call is executed directly
        |
AUDIT AND OBSERVABILITY          prompt version, model, latency, token counts, actor, tenant, result
```

## Mapping to existing components

| Target stage | Exists today | Where |
| --- | --- | --- |
| Input validation | Yes | Zod schemas in every route |
| Tenant isolation | Yes | `org_id` from session; tests |
| Structured output | Yes for API payloads, not for a model | Zod response construction |
| Tool authorization | Partly: human approval + RBAC for SOAR | `routes/automation.js` |
| Risk classification | Yes | `DESTRUCTIVE` action set |
| Controlled execution | Yes, but simulated | `execute()` records steps; no EDR/firewall call |
| Audit | Yes | hash chained `audit_logs` |
| Prompt templates | No | - |
| Model routing / provider | No | - |
| Agent memory / context | No | - |
| Evaluation corpus | No | - |

## Non-negotiable rules for any future implementation

1. Prompt text never grants permission. Authorization is resolved server side from the session.
2. Model output is untrusted input. It is schema validated before use and never executed as code.
3. External content (event descriptions, URLs, email, logs, threat feeds) is data. It is delimited and labelled; the model is instructed to never follow instructions found inside it.
4. Tool calls pass through one gateway with authentication, role, tenant, input schema, risk class, approval when required, and audit.
5. Destructive actions always require human approval, regardless of workflow configuration or model confidence.
6. Secrets, session tokens, passwords and service keys never enter a prompt, a log or a model response.
7. Every prompt has a version and every response stores the version, model id and latency for reproducibility.
8. Deterministic detection remains the baseline and stays available when the provider fails.
9. A regression corpus covers direct injection, indirect injection, cross-tenant attempts, malformed JSON, hallucinated findings and unsafe automation proposals.
10. Product copy must not describe probabilistic output as verified evidence.

## Implementation plan if AI is approved

| Step | Work | Depends on |
| --- | --- | --- |
| 1 | Choose a provider and a single server-side client; no browser keys | Budget, data residency decision |
| 2 | Add `prompts` table with version, template, variables, checksum | Schema migration |
| 3 | Add `ai_runs` table: prompt version, model, tokens, latency, status, redacted input hash | Migration |
| 4 | Implement template renderer that escapes untrusted variables and never concatenates instructions | Step 2 |
| 5 | Implement one read-only use case (incident summary) with schema validation and fallback | Steps 1-4 |
| 6 | Add evaluation corpus and CI job | Step 5 |
| 7 | Only then consider a tool-calling agent, behind the gateway and approval layer | Step 6 |

None of steps 1-7 is implemented in this build.
