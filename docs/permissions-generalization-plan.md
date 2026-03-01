# Feature Plan: Generalized Permissions for SSH + Regular Bash

## Goal
Extend the current SSH-focused permission model into a domain-aware permissions system that can also govern regular `bash` commands in pi.

## Requested additions
1. New command: `/permissions`
2. Config keys for global/per-project JSON files
3. Keep existing SSH behavior intact and compatible

---

## Product intent
- Preserve current secure defaults for SSH.
- Introduce bash permissions in a controlled, opt-in rollout.
- Avoid breaking existing `/ssh-policy` workflows.

Recommended default posture:
- `permissions.ssh.enabled = true`
- `permissions.bash.enabled = false` (opt-in initially)
- `permissions.bash.mode = prompt` when enabled

---

## Proposed architecture

## 1) Domain-aware permission model
Add permission domain tag to approvals/grants:
- `domain: "ssh" | "bash"`

Fingerprint input becomes:
- `domain + target(optional) + normalizedCommandPattern`

Notes:
- `ssh` retains `target` scoping.
- `bash` uses local-context scoping (project/session/global) without remote target.

## 2) Unified command surface
Add `/permissions` command for both domains.
Keep `/ssh-policy` as a compatibility alias to `/permissions` behavior for SSH.

### `/permissions` MVP UX (requested)
- Running `/permissions` opens a configuration panel/menu.
- Initial MVP includes only two checkboxes:
  - **Enable SSH permissions**
  - **Enable Bash permissions**
- User can Save/Cancel.
- Save persists settings to merged global/project config according to active scope rules.

## 3) Config model
Add config section in both global and project JSON:

```json
{
  "permissions": {
    "ssh": { "enabled": true },
    "bash": {
      "enabled": false,
      "mode": "off",
      "scope": "all"
    },
    "storage": {
      "globalPath": "~/.pi/agent/permissions.json",
      "projectPath": "<project>/.pi/permissions.json"
    }
  }
}
```

Modes:
- `off`: do nothing for bash commands
- `prompt`: ask approval but allow deny/once/session/project controls
- `enforce`: block unapproved commands in no-UI and interactive flows

---

## Phased delivery

### Phase A — Spec and schema prep
- Define JSON schema updates.
- Decide migration path from existing ssh-only policy files.
- Freeze compatibility behavior for `/ssh-policy`.

### Phase B — `/permissions` panel MVP
- Implement `/permissions` to open panel/menu.
- Add two checkbox controls only:
  - Enable SSH permissions
  - Enable Bash permissions
- Implement Save/Cancel and config persistence.

### Phase C — Config + storage plumbing
- Load merged config (global + project).
- Honor storage path overrides.
- Add schema version/migration tests.
- Ensure panel reflects merged effective values.

### Phase D — Extended `/permissions` controls (post-MVP)
- Add optional advanced actions (status/list/reload/mode/clear) after panel MVP is stable.

### Phase E — Bash permissions (prompt mode)
- Add domain `bash` guard path for `tool_call(bash)` + `user_bash`.
- Reuse analyzer/pattern extraction pipeline.
- Prompt with domain-labeled summaries.

### Phase F — Enforce mode and no-UI behavior
- Add strict no-UI deny semantics for unapproved bash commands when enabled.
- Add fail-closed tests for uncertain parsing.

### Phase G — Compatibility + deprecation UX
- Keep `/ssh-policy` alias.
- Add warning suggesting `/permissions`.
- Document migration and examples.

---

## Test plan (TDD)
For each phase:
1. Add failing tests first.
2. Implement minimal fix.
3. Run full suite.

Critical tests:
- `/permissions` command parsing and state updates
- schema migration and config merge precedence
- ssh behavior parity (no regressions)
- bash mode transitions (`off|prompt|enforce`)
- no-UI enforcement correctness
- alias compatibility (`/ssh-policy`)

---

## Risks and mitigations
- **Risk:** over-broad approvals across domains
  - **Mitigation:** domain-tagged fingerprints and explicit scope semantics.
- **Risk:** config complexity
  - **Mitigation:** strict schema + defaults + status command visibility.
- **Risk:** regressions in existing SSH workflows
  - **Mitigation:** parity tests + compatibility alias + staged rollout.

---

## Acceptance criteria
- `/permissions` exists and can show status/list/reload at minimum.
- Config keys work from both global and project JSON.
- Existing SSH policy behavior remains intact.
- Bash permissions can be enabled explicitly and enforced in no-UI mode.
- `/ssh-policy` remains available as compatibility alias.
