# Product Backlog

Last updated: 2026-02-27

## Current state
- Existing `TODO.md` is a **refactor checklist** and is now complete.
- This file tracks **forward-looking features and improvements**.

---

## Recommended execution order (next)

1. [x] Add strict-mode integration tests for parser uncertainty behavior.
2. [x] Add cross-analyzer consistency corpus.
3. [x] Decide and execute migration from `DIRECT_SSH_PARSE_FAILURE_MODE="compat"` to `"strict"`.
4. [x] Epic kickoff: URL-specific matching for destructive curl methods (spec + failing tests).
5. [x] Implement curl URL-scoped destructive-method patterns + approval compatibility.
6. [x] Epic kickoff: wget method matrix + failing tests.
7. [x] Implement wget analyzer integration + parity tests.
8. [ ] Real-world integration testing in controlled environment and capture findings.
9. [ ] Add CI job for test matrix + lint/type checks.
10. [ ] Prompt transparency/policy explain UX improvements.
11. [ ] Plan + implement generalized command permissions for non-SSH bash commands (`/permissions` + config).

---

## P0 — Security / correctness

- [x] Decide and execute migration from `DIRECT_SSH_PARSE_FAILURE_MODE="compat"` to `"strict"`.
  - Runtime mode is now strict-only fail-closed.
  - Regression coverage added/updated for strict uncertain-parse behavior in matcher and guard integration tests.

- [x] Add strict-mode integration tests for parser uncertainty behavior.
  - [x] Validate no-UI deny behavior on uncertain parse cases.
  - [x] Validate direct SSH-family blocking remains fail-closed.

- [x] Add cross-analyzer consistency corpus.
  - Same command corpus should preserve expected outcomes across matcher + pattern analyzer.

---

## P1 — Policy UX & approvals

- [ ] Epic: Generalized permissions for regular bash commands (`/permissions`).
  - User story: as a user, I want the same approval model currently used for `ssh_bash` to be optionally applicable to regular `bash` commands in pi.
  - Scope includes command UI and config controls for global + per-project policy files.
  - Implementable chunks:
    - [ ] Define policy model split:
      - `ssh_permissions` (existing behavior)
      - `bash_permissions` (new behavior)
      - shared grant schema where possible.
    - [ ] Add config keys (global + project JSON) to enable/disable and tune behavior:
      - `permissions.ssh.enabled` (default true)
      - `permissions.bash.enabled` (default false initially)
      - `permissions.bash.mode` (`off|prompt|enforce`)
      - `permissions.bash.scope` (`all|high_risk_only`)
      - `permissions.storage.globalPath` / `permissions.storage.projectPath` overrides.
    - [x] Define `/permissions` panel UX (MVP first):
      - Running `/permissions` opens a configuration panel.
      - MVP panel contains two checkboxes only:
        - `Enable SSH permissions`
        - `Enable Bash permissions`
      - Save/cancel actions persist to config JSON.
      - Advanced subcommands (`status|list|clear|reload|mode`) deferred until after panel MVP.
    - [x] Add strict TDD tests for `/permissions` panel open/render + checkbox state transitions. (RED: failing tests added in `tests/permissions-mvp-red.test.ts`)
    - [x] Introduce policy store schema/version update for config + dual-domain grants.
    - [x] Add guard path for regular `bash` permissions (shared analyzer pipeline, domain-tagged fingerprints).
    - [x] Reuse/extend prompt messaging to clearly indicate domain (`ssh` vs `bash`) and allow-pattern summary.
    - [x] Add migration compatibility for existing `ssh-policy` files/commands.
    - [x] Keep `/ssh-policy` as compatibility alias (deprecation warning + mapped behavior).
    - [x] Add integration tests for no-UI behavior and fail-closed semantics in `bash` domain.
    - [x] Document examples for both domains and safe rollout defaults.


- [ ] Improve approval dialog transparency.
  - Show which patterns are already approved vs missing for the target.
  - Keep full command visibility for long commands.

- [ ] Add prompt rendering tests.
  - Coverage for `allowPatternSummary`, `missingPatternSummary`, and restricted-option flows.

- [ ] Optional policy explain command.
  - New subcommand idea: `/ssh-policy explain <target> <command>`
  - Output match status, generated patterns, and why auto-approval did/did not happen.

---

## P1 — Parser/analyzer extensions

- [ ] Epic: URL-specific matching for potentially destructive curl methods.
  - User story: as a user, I want `curl` methods like POST/PUT/PATCH/DELETE to be permission-matched by URL/host scope (not just method-wide), so approvals can be narrow (e.g., allow POST to `api.example.com` only).
  - Suggested pattern format: `curl POST api.example.com/*` (or equivalent canonical host/path scope).
  - Keep GET behavior broad unless explicitly configured otherwise.
  - Implementable chunks:
    - [x] Define URL canonicalization spec for permissions (scheme handling, host case-folding, default ports, path normalization, query handling).
    - [x] Add failing tests for curl URL extraction + canonicalization in analyzer unit tests.
    - [x] Extend `src/shell/analyzers/curl-patterns.ts` to emit host/path-scoped patterns for destructive methods.
    - [x] Keep existing `curl GET *` behavior as default and add tests proving no regression.
    - [x] Update pattern union/approval checks in `src/index.ts` (if needed) to support new URL-scoped pattern matching.
    - [ ] Update prompt summaries to display URL-scoped patterns clearly (and add prompt rendering tests).
    - [x] Add migration/compat handling for existing stored `curl METHOD *` approvals (backward compatibility strategy).
    - [ ] Add integration tests covering multi-command chains with mixed curl hosts/methods.

- [ ] Epic: Add wget analyzer with method-aware matching similar to curl.
  - User story: as a user, I want `wget` commands handled like `curl`, separated into GET/POST/etc where flags imply request method.
  - Include URL/host scoping for destructive methods, aligned with curl policy behavior.
  - Implementable chunks:
    - [x] Define wget method inference matrix from flags (`--post-data`, `--method`, body options, upload-related flags if applicable).
    - [x] Add failing unit tests for wget method detection/parsing edge cases.
    - [x] Implement `src/shell/analyzers/wget-patterns.ts` method-aware parsing.
    - [ ] Add failing unit tests for wget URL extraction/canonicalization.
    - [ ] Implement wget URL/host canonicalization helpers and URL-scoped patterns (aligned with curl URL-scope epic).
    - [x] Integrate wget analyzer into `src/shell/analyzers/command-patterns.ts` dispatch.
    - [x] Add parity tests for chains combining curl + wget.
    - [x] Ensure reusable-unsafe/completeness semantics match curl behavior when parsing is incomplete.
    - [x] Update user-facing prompt summaries/examples for wget patterns.

- [ ] Expand curl method coverage tests for additional edge forms.
  - e.g., inline forms and mixed option order stress-cases.

- [ ] Add mixed-case executable/wrapper regression tests in matcher.
  - e.g., `/usr/bin/SSH`, `SUDO -- SSH ...`.

- [ ] Evaluate additional command-family analyzers.
  - Candidates: `kubectl`, `git`, `systemctl` (subcommand-aware reusable patterns).

---

## P2 — Reliability / operations

- [ ] Real-world integration testing in controlled environment.
  - Capture findings in `docs/` (per AGENTS open next step).

- [ ] Add CI job for test matrix + lint/type checks.
  - Include parser/analyzer module tests explicitly.

- [ ] Address Node warning in tests (`MODULE_TYPELESS_PACKAGE_JSON`).
  - Decide whether to set `"type": "module"` in `package.json`.

---

## P3 — Documentation

- [ ] Add a short “Architecture” section in `README.md` linking:
  - `src/shell/README.md`
  - `docs/parser-refactor-phases-1-5.md`

- [ ] Document parse-failure mode policy and migration intent (compat -> strict).

---

## Intake template (for new backlog items)

When adding a new item, include:
- **Problem**
- **User impact**
- **Proposed change**
- **Security impact** (if any)
- **Tests to add first (TDD)**
- **Acceptance criteria**
