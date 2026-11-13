# SOAR verification report

## 1. What the workflow engine does

A response workflow has a trigger and an ordered list of actions. Creating or editing a workflow with a destructive action forces `requiresApproval` on, server side (`backend/src/routes/automation.js:45` and `:68`). Running a workflow that needs approval creates an execution in `pending_approval` with a 30 minute expiry and records only an `awaiting_approval` step; nothing is executed.

Approval is a separate authenticated request requiring analyst or admin. It checks the current status, the expiry and the approver, then records the remaining steps. A reused or expired approval is refused.

## 2. What "executed" means here

No firewall, endpoint agent or identity provider is connected. The engine therefore records each action as `simulated` with a sentence explaining that no external system was contacted (`backend/src/routes/automation.js:93`). The execution record is honest about the outcome; it does not claim the host was isolated or the address blocked.

## 3. Verified behaviour

Covered by the backend suite (`backend/tests/workflow.test.mjs` and the automation route tests):

- a destructive workflow cannot be created without approval
- a run requiring approval stops at `pending_approval`
- an approval records the remaining steps and completes the execution
- an expired approval is refused and the execution is marked expired
- a viewer cannot run or approve
- the execution log distinguishes simulated steps from completed ones

Latest full run: 121 backend tests, 119 passed, 2 skipped (Redis integration skipped without a server), 0 failed.

## 4. External verification

None. There is no test firewall, EDR or identity provider on this host, and acting on a real system without explicit authorisation would violate the rules of engagement. Every action remains SIMULATED.

## 5. What a real adapter needs

For each action type:

1. An adapter interface with an explicit allowlist of targets.
2. Credentials in the backend environment only.
3. A preflight check that the target belongs to the organization.
4. Server side approval, unchanged.
5. An idempotency key so a retry does not repeat a destructive action.
6. A short timeout and a recorded external response.
7. Verification of the external state after the call, not just a 2xx.
8. An audit record with the external reference and the result.
9. A documented rollback where the provider supports one.

Until one adapter passes 1 to 9 against a staging system, the status of every action is SIMULATED.

## 6. Status

| Item | Status |
| --- | --- |
| Approval gate | IMPLEMENTED, TESTED |
| Expiry and single use | IMPLEMENTED, TESTED |
| Honest simulated labelling | IMPLEMENTED, TESTED |
| Real external action | NOT IMPLEMENTED |
| External verification | NOT VERIFIED |
