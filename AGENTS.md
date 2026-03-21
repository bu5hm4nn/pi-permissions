# AGENTS.md — Project Handoff Notes

## Project
`pi-permissions`

Goal: a pi extension that provides `ssh_bash` with per-command approvals and blocks direct SSH-family access outside the tool.

## Current State
Implementation is in `src/` and last subagent quality gate returned **PASS**.

### Implemented modules
- `src/index.ts` — extension wiring (tool, guards, lifecycle, audit)
- `src/commands/ssh-policy.ts` — `/ssh-policy` command set
- `src/policy/fingerprint.ts` — normalization, fingerprints, reusable-unsafe detection
- `src/policy/store.ts` — secure policy storage (global + project-scoped files)
- `src/policy/trust.ts` — trust registry + invariants
- `src/ssh/matcher.ts` — direct SSH-family matcher with fail-closed behavior
- `src/ssh/execute.ts` — SSH execution, streaming, timeout/abort, truncation/full output
- `src/ssh/validate.ts` — input validation
- `src/ui/prompt.ts` — interactive approval prompt

## Important Design Sources
- Spec: `docs/ssh-permission-extension-spec.md`
- Review snapshots:
  - `docs/subagent-review-results.md`
  - `docs/subagent-rereview-results.md`

## Working Conventions For Next Agent
1. **Always use the `implementation-coder` subagent for code changes** (mandatory project rule).
2. **Always run `implementation-reviewer` after implementation changes** before finalizing.
3. **Follow strict TDD (test-first)**:
   - Write or update a failing test that captures the requested behavior/regression **before** code changes.
   - Confirm the test fails for the expected reason.
   - Implement the minimal code change to make the test pass.
   - Re-run the full relevant test suite and report results.
4. Make small, testable changes.
5. Keep behavior aligned with the spec unless user asks for changes.
6. If changing security-sensitive behavior, run reviewer subagent before finalizing.

## Suggested Subagent Flow
- Red step (TDD): `implementation-coder` adds/updates failing test first and shows failure.
- Green step (TDD): `implementation-coder` implements minimal fix and runs tests.
- Verification: `implementation-reviewer` validates behavior + security posture.
- Repeat Red→Green→Review until reviewer says PASS.

## Security-Critical Areas (handle carefully)
- `src/ssh/matcher.ts` (fail-closed command parsing)
- `src/policy/store.ts` and `src/policy/trust.ts` (secure file IO, ownership/perms, atomic writes)
- `src/index.ts` (no-UI denial logic, startup self-check, emergency fail-closed mode)

## Quick Validation Checklist
- `ssh_bash` prompts correctly for new commands.
- No-UI mode denies unapproved fingerprints.
- Direct `bash`/`user_bash` SSH-family invocations are blocked.
- `/ssh-policy list|clear|revoke|reload` behaves as specified.
- Timeout/abort in SSH execution returns error semantics.
- Truncation always provides `fullOutputPath` when truncated.

## Available Project Agents

### `pattern-improver`
Analyzes commands logged in `src/policy/analysis-log.ts` that need better pattern extraction. Identifies common command structures and proposes/implements pattern improvements.

Usage: `@pattern-improver` with the analysis log path (e.g., `~/.pi/agent/analysis-log.jsonl`)

## Open Next Step
Run real-world integration testing in a controlled environment and capture findings in `docs/`.
