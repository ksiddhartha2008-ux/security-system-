# Documentation

Start with the [project README](../README.md).

## Architecture and data

- [ARCHITECTURE.md](ARCHITECTURE.md) - components, data model, request flow
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - endpoint reference
- [DASHBOARD_DATA_DICTIONARY.md](DASHBOARD_DATA_DICTIONARY.md) - every dashboard metric and its query

## Security

- [SECURITY.md](SECURITY.md) - controls, threat model, reporting
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md) - findings with severity and evidence
- [SECURITY_REMEDIATION_PLAN.md](SECURITY_REMEDIATION_PLAN.md) - phased plan and status
- [SECURITY_TEST_MATRIX.md](SECURITY_TEST_MATRIX.md) - control to test mapping
- [SECURITY_PROGRESS.md](SECURITY_PROGRESS.md) - verified progress and open items
- [SECURITY_DEPENDENCY_REPORT.md](SECURITY_DEPENDENCY_REPORT.md) - dependency audit
- [PRODUCTION_SECURITY_CHECKLIST.md](PRODUCTION_SECURITY_CHECKLIST.md) - pre-deployment gate

## AI and simulation

- [PROMPT_ENGINE_SECURITY_AUDIT.md](PROMPT_ENGINE_SECURITY_AUDIT.md) - confirms no LLM exists
- [PROMPT_ENGINE_ARCHITECTURE.md](PROMPT_ENGINE_ARCHITECTURE.md) - requirements for a future model feature
- [SIMULATION_ENGINE.md](SIMULATION_ENGINE.md) - scenarios, pipeline, idempotency
- [THREAT_SIMULATION_LAB.md](THREAT_SIMULATION_LAB.md) - lab walkthrough

## Demo data

- [DATA_FLOW_AUDIT.md](DATA_FLOW_AUDIT.md) - why a workspace showed zero and what changed
- [DEMO_DATA_GUIDE.md](DEMO_DATA_GUIDE.md) - generate, classify and reset demo data

## Website protection

- [website/STATUS.md](website/STATUS.md) - workflow, task status, launch gates and verdict
- [website/REUSE_MAP.md](website/REUSE_MAP.md) - what existing code the feature reuses
- [website/DECISIONS.md](website/DECISIONS.md) - binding design decisions and owner defaults
- [website/EVENT_MAPPING.md](website/EVENT_MAPPING.md) - SDK event types to stored events
- [website/HTTP_API.md](website/HTTP_API.md) - raw ingestion API for other languages
- [website/THREAT_MODEL.md](website/THREAT_MODEL.md) - abuse cases and the tests that cover them
- [website/SCALABILITY_PLAN.md](website/SCALABILITY_PLAN.md) - shared rate limiting and the PostgreSQL migration plan
- [website/SECRET_SCANNING.md](website/SECRET_SCANNING.md) - key pattern and scanning commands

## Integrations

- [MIROFISH_INTEGRATION.md](MIROFISH_INTEGRATION.md)
- [API_ANYTHING_INTEGRATION.md](API_ANYTHING_INTEGRATION.md)

## Operations and status

- [DEPLOYMENT.md](DEPLOYMENT.md) - local, Docker and reverse proxy
- [PROJECT_STATUS.md](PROJECT_STATUS.md) - module status and evidence
- [IMPLEMENTATION_LOG.md](IMPLEMENTATION_LOG.md) - build history
- [REMAINING_WORK.md](REMAINING_WORK.md) - prioritised backlog
