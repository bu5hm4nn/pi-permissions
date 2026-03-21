# SSH Permission Extension Spec (pi)

## 0) Scope and objective

Design a pi extension that:
1. Exposes a dedicated SSH execution tool (`ssh_bash`) for remote shell commands.
2. Prompts for user approval for each **new** SSH command fingerprint with options:
   - `1. Allow Once`
   - `2. Allow for this session`
   - `3. Allow for this Project`
   - `4. Deny`
3. Blocks SSH-family access that does not go through `ssh_bash`.

This is an implementation-ready specification aligned with pi extension APIs (`registerTool`, `tool_call`, `user_bash`, `registerCommand`, `ctx.ui.*`).

---

## 1) Frozen policy decisions

Final user-confirmed decisions:

1. **Session scope**
   - `Allow for this session` is valid only for the current conversation session.
   - Cleared on `/new`, `/resume`, `/fork`, and process restart/reload.

2. **Deny semantics**
   - `Deny` applies to the current attempt only.
   - No deny persistence by default.

3. **No-UI behavior**
   - If UI is unavailable, only persistent policy approvals may pass.
   - New/unapproved fingerprints are denied.

4. **SSH blocking strictness outside extension tool**
   - Block only direct SSH-family commands:
     - `ssh`, `scp`, `sftp`, `sshpass`, `mosh`

5. **Policy storage scope**
   - Use both global and project policy stores.

6. **Permission identity key**
   - Fingerprint is based on `target + normalizedCommand` (no cwd in key).

### Effective policy sets (explicit)
- `interactiveEffective = session ∪ global ∪ trustedProject`
- `noUiEffective = global ∪ trustedProject`
- Session grants are **ignored in no-UI mode**.

---

## 2) Extension boundaries

### In scope
- `ssh_bash` tool for remote command execution over SSH.
- Per-fingerprint approval workflow.
- Session/global/project policy resolution and persistence.
- SSH-family blocking in:
  - `tool_call` for built-in `bash`
  - `user_bash` for `!` / `!!` commands.

### Out of scope
- Persistent remote interactive shell sessions.
- SSH key management, passphrase/password UX.
- Full shell AST equivalence for command normalization.

### Security boundary (precise)
- This extension guarantees blocking of **direct SSH-family command invocations** outside `ssh_bash`.
- It does **not** claim to detect arbitrary indirection that resolves to SSH at runtime (non-goal).

---

## 3) Tool schema and UX

## Tool name
- `ssh_bash`

## Parameters
```ts
Type.Object({
  target: Type.String({ description: "SSH target, e.g. user@host" }),
  command: Type.String({ description: "Remote bash command" }),
  cwd: Type.Optional(Type.String({ description: "Remote working directory (optional)" })),
  timeout: Type.Optional(Type.Number({ description: "Timeout in seconds" }))
})
```

## Input validation rules
- `target`
  - trim required
  - must not be empty
  - must not start with `-` (prevents SSH option injection)
  - must not contain NUL, `\r`, or `\n`
  - max length 255
- `command`
  - must be non-empty after trim
- `cwd` (if present)
  - must not contain NUL, `\r`, or `\n`
- `timeout` (if present)
  - integer seconds in `[1, 3600]`

## Tool description (LLM-facing)
- Executes a remote bash command over SSH.
- Requires explicit user approval for new command fingerprints.
- Reuses grants from session/global/project policy according to mode.

## Result details shape
```ts
{
  exitCode?: number,
  truncated?: boolean,
  fullOutputPath?: string,
  decision: "allow_once" | "allow_session" | "allow_project" | "auto_allow_policy" | "deny" | "deny_no_ui",
  decisionScope: "none" | "session" | "project" | "global",
  fingerprint: string,
  target: string
}
```

---

## 4) Decision semantics: Allow Once

`Allow Once`:
- Executes only the current invocation.
- No session/global/project write.
- Next same fingerprint prompts again.

---

## 5) Decision semantics: Allow for this session

`Allow for this session`:
- Add fingerprint to in-memory session grant set.
- Valid only in current conversation session.
- Cleared on session boundaries and restart/reload.
- If `reusableUnsafe` (defined in §6), this option is rejected and user must choose again.

Lifecycle handling:
- Initialize empty set on `session_start`.
- Clear on `session_switch` and `session_fork`.

---

## 6) Decision semantics: Allow for this Project

`Allow for this Project`:
- Persist fingerprint to user-owned project policy file.
- Effective immediately and after restart.
- Included in effective policy only when project is trusted.

Safety gate for reusable approvals (required because key excludes `cwd`):
- Define `reusableUnsafe = (cwd is provided) OR (command is relative-path-sensitive, e.g. contains `./` or `../` execution contexts)`.
- If `reusableUnsafe` is true, reusable approvals are not allowed:
  - `Allow for this session` rejected
  - `Allow for this Project` rejected
- UI still shows all 4 options; if user picks a rejected reusable scope,
  extension explains and asks for another choice (`Allow Once` or `Deny`).

Failure behavior:
- If persistence write fails, execution is denied (fail closed) with explicit error.

---

## 7) Permission key normalization and fingerprinting

## Canonicalization
- `targetCanonical = target.trim()`
- `commandCanonical`:
  - normalize line endings: `\r\n`/`\r` → `\n`
  - trim surrounding whitespace
  - remove trailing blank lines

## Key material
```txt
v1\n<targetCanonical>\n<commandCanonical>
```

## Fingerprint
- `fingerprint = sha256(keyMaterial).hex`

## Identity rule
- Equality means identical fingerprint.
- `cwd` is intentionally **not** part of key (per frozen decision #6).

---

## 8) Policy stores and schema

## Deterministic project root
Resolve once at runtime start:
1. nearest ancestor containing `.git`
2. else startup cwd

Use this fixed root for all project policy operations.

## File locations
- Global policy: `~/.pi/agent/ssh-policy-global.json`
- Project policy directory (user-owned, per project):
  - `~/.pi/agent/ssh-policy-projects/<projectId>.json`
- Project trust registry:
  - `~/.pi/agent/ssh-policy-trust.json`

Where:
- `projectId = sha256(realpath(projectRoot)).hex`

## Trust model
- Persistent project grants are stored outside the repository in user-owned config space.
- Trust is attached to canonical `realpath(projectRoot)` via trust registry.
- Trust can be granted interactively when user first chooses `Allow for this Project`.
- In no-UI mode, project grants are used only if project is trusted.

## Effective resolution
- Additive model only:
  - `effective = union(global.grants, project.grants if trusted, session if interactive)`
- No project subtraction/override of global grants in v1.

## JSON schema (v1)
```json
{
  "version": 1,
  "updatedAt": "2026-02-26T10:00:00.000Z",
  "grants": [
    {
      "fingerprint": "<sha256-hex>",
      "target": "user@host",
      "commandPreview": "kubectl get pods -A",
      "createdAt": "2026-02-26T10:00:00.000Z"
    }
  ]
}
```

### Policy store invariants
- dedupe by `fingerprint` (upsert semantics)
- preserve earliest `createdAt` for existing fingerprint
- always update `updatedAt` on mutation
- ignore unknown fields for forward compatibility

## Trust registry schema (v1)
```json
{
  "version": 1,
  "updatedAt": "2026-02-26T10:00:00.000Z",
  "trustedProjects": [
    {
      "projectId": "<sha256-realpath>",
      "projectRootRealpath": "/abs/path/to/project",
      "createdAt": "2026-02-26T10:00:00.000Z"
    }
  ]
}
```

### Trust invariants
- dedupe by `projectId`
- `projectId` must match `sha256(projectRootRealpath)`
- `projectRootRealpath` must be canonical realpath
- unknown fields ignored for forward compatibility

---

## 9) Permission prompt flow

## Prompt options (exact labels)
- `1. Allow Once`
- `2. Allow for this session`
- `3. Allow for this Project`
- `4. Deny`

## Decision algorithm
1. Validate tool input.
2. Compute fingerprint.
3. Load policies (global/project/trust) and session grants.
4. Build effective set:
   - interactive: `session ∪ global ∪ trustedProject`
   - no-UI: `global ∪ trustedProject`
5. **Pattern-based approval**: if command has extractable patterns:
   - Extract command patterns (e.g., `curl POST https://api.example.com/items` → `curl POST https://api.example.com/items`).
   - Compute fingerprint for each pattern.
   - If all pattern fingerprints exist in effective set → execute (`auto_allow_policy`).
   - If any pattern fingerprint is missing → proceed to prompt.
   - **Fallback equivalence**: Commands with URL-scoped patterns (curl/wget mutating methods) may have a fallback pattern (e.g., `curl POST *`). If the fallback fingerprint is approved, the URL-scoped command is also considered approved. This enables approving broad patterns like `curl POST *` to cover specific URLs.
6. If fingerprint exists in effective set → execute (`auto_allow_policy`).
7. If no-UI and not approved → deny (`deny_no_ui`).
8. If interactive and not approved:
   - show select with 4 options.
   - dialog cancel/timeout => `Deny`.
9. Apply decision:
   - once: execute
   - session:
     - if `reusableUnsafe`, reject selection and re-prompt
     - else add to session set, execute
   - project:
     - if `reusableUnsafe`, reject selection and re-prompt
     - else:
       - ensure project trust (interactive bootstrap if needed)
       - if trust denied/cancelled, deny with no trust/grant writes
       - if trusted, persist grant then execute
   - deny: block
10. Any persistence/parse error on an unapproved command => deny (fail closed).

---

## 10) Pattern-based approval

### Intent
Commands like `curl -X POST https://api.example.com/items` contain extractable patterns (`curl POST https://api.example.com/items`). Users can pre-approve these patterns for reusable approvals instead of approving each exact command fingerprint.

### Pattern extraction
- Parse command to extract executable and arguments.
- For curl/wget with method verbs (GET, POST, PUT, DELETE, PATCH), extract `<method> <url>` pattern.
- For other commands, extract simplified pattern representation.
- Commands may return multiple patterns (e.g., compound commands).
- Extraction may fail (incomplete analysis) – in this case, pattern-based approval is not available.

### URL-scoped patterns
- Mutating HTTP methods (POST, PUT, DELETE, PATCH) produce URL-scoped patterns: `curl POST https://api.example.com/items`.
- Safe methods (GET, HEAD) produce broad patterns: `curl GET *`.
- URLs are canonicalized (protocol + hostname + port + pathname, no credentials/params/hash).

### Fallback equivalence
- URL-scoped patterns have a fallback pattern: `curl POST https://api.example.com/items` → fallback `curl POST *`.
- If the fallback fingerprint is approved, the URL-scoped command is also considered approved.
- This allows users to approve broad patterns like `curl POST *` once, covering all POST requests.
- Security: fallback equivalence only applies when pattern analysis is complete (`complete=true`).

---

## 10) SSH execution pipeline

## Process execution
Use `spawn("ssh", sshArgs, { stdio: ["ignore", "pipe", "pipe"] })`.

Base options:
- `-o BatchMode=yes`
- `-o ConnectTimeout=10`

## Remote command construction
- If `cwd` absent: run `command` via remote `bash -lc`.
- If `cwd` present: run `cd <quotedCwd> && <command>` via `bash -lc`.

Quoting requirement:
- Implement POSIX single-quote escaping helper for `cwd` insertion.

## Streaming and truncation
- Stream stdout/stderr updates.
- Tail truncation limits consistent with built-in bash behavior:
  - max 50KB OR 2000 lines (whichever first)
- If truncated, write full output to temp file and include `fullOutputPath` in details.

## Cancellation and timeout
- Respect AbortSignal cancellation.
- Respect per-call timeout.
- Deterministic error mapping:
  - abort => cancelled output message
  - timeout => timeout message
  - non-zero exit => include output + exit code

---

## 11) Block non-extension SSH access

## 11.A `tool_call` guard for `bash`
On `tool_call` where `toolName === "bash"`, inspect `input.command`.

### Matcher contract (direct commands only)
- Use a shell parser (AST/tokenizer) that is quote-aware.
- Parse command lists across control operators:
  - `;`, `&&`, `||`, `|`, `&`, newline
- For each command node, resolve executable head token as follows:
  1. remove leading env assignments (`KEY=VALUE`)
  2. recursively unwrap known wrappers with option parsing and `--` handling:
     - wrappers: `sudo`, `env`, `command`, `builtin`, `exec`, `nohup`, `time`, `nice`
     - if wrapper options/arguments make target command position ambiguous, treat as unresolved
  3. take resulting executable token basename (supports `/usr/bin/ssh` form)
- If resolved basename is in blocked set `{ssh, scp, sftp, sshpass, mosh}` => block.
- If parser cannot confidently resolve head command (including unresolved wrapper semantics) => block (fail closed).

Return:
```ts
{ block: true, reason: "Direct SSH-family commands are blocked. Use ssh_bash." }
```

## 11.B `user_bash` guard for `!`/`!!`
Apply same matcher to `event.command`.
If matched, return full replacement result:
```ts
{
  result: {
    output: "Blocked: direct SSH-family commands are disabled. Use ssh_bash tool.",
    exitCode: 126,
    cancelled: false,
    truncated: false
  }
}
```

---

## 12) Management commands

## `/ssh-policy list [scope]`
Scopes: `session | project | global | effective` (default: `effective`)

Output fields:
- index
- fingerprint prefix
- target
- commandPreview
- createdAt
- source scope

## `/ssh-policy clear <scope>`
Scopes: `session | project | global | all`
- interactive mode: confirmation required for persistent scopes
- no-UI: clear executes directly

## `/ssh-policy revoke <scope> <fingerprintPrefix>`
Scopes: `session | project | global`
Rules:
- prefix must be hex and at least 8 chars
- 0 matches => explicit error
- >1 matches => explicit ambiguity error (ask for longer prefix)
- exactly 1 match => revoke

## `/ssh-policy reload`
- Re-read policy and trust files from disk
- Keep in-memory session grants unchanged

## `/ssh-policy improve`
Lists commands from the analysis log that need pattern improvement.

Purpose:
- Shows commands that produced incomplete pattern analysis or wildcard-only patterns
- Helps identify gaps in the pattern extraction system
- Provides visibility for manual review and potential pattern improvements

Output:
- Analysis log path
- Number of commands needing improvement
- Up to 20 recent entries showing:
  - Index number
  - Analysis completeness status ([✓] complete, [✗] incomplete)
  - Command preview (truncated)
  - Target
  - Extracted patterns
  - Reason (if any)

Legend:
- `[✓]` = analysis complete but patterns are wildcards (needs improvement)
- `[✗]` = analysis incomplete (command could not be fully parsed)

The analysis log is stored at `~/.pi/agent/analysis-log.jsonl` and contains only
`commandPreview` fields (no full command storage for security).

---

## 13) Security and observability

## Fail-closed defaults
- Unknown/unreadable policy state for unapproved command => deny.
- Prompt unavailable/cancelled/timed out => deny.
- Project persistence write failure => deny.

## Secure file IO requirements
- create files with `0600`
- on read: require owner uid == current user and reject group/world-writable files
- reject symlink targets for policy/audit writes
- atomic writes via temp file + rename
- enforce max policy size (e.g., 1MB) and max grants (e.g., 10k)

## Data minimization
- Persist `commandPreview` only (sanitized, single-line, bounded length, e.g. 120 chars)
- Do not persist full command body in policy store by default

## Audit log
Path: `~/.pi/agent/ssh-policy-audit.log` (JSONL)

Event fields:
- `timestamp`
- `sessionId` (if available)
- `toolCallId`
- `target`
- `fingerprint`
- `decision` (`allow_once|allow_session|allow_project|deny|auto_allow_policy|deny_no_ui`)
- `scope` (`none|session|project|global`)
- `policySource` (`session|project|global|none`)
- `commandPreview`
- `result` (`executed|blocked|failed`)
- `exitCode` (if executed)

---

## 14) Compatibility and extension interaction

1. **Sandbox extension**
   - Compatible; blocking happens before local bash execution.

2. **Plan-mode extension**
   - If plan mode disables write/exec classes, keep `ssh_bash` disabled unless explicitly enabled by plan policy.

3. **Bash tool overrides**
   - `tool_call` guard still applies by tool name `bash`.
   - `user_bash` guard remains independent.

4. **No-UI modes**
   - No prompts.
   - Only global/trusted-project persistent grants are honored.

5. **Guard health checks**
   - On startup, extension runs a self-check of matcher and policy loading.
   - On fatal guard init failure, extension enters emergency fail-closed mode:
     - `ssh_bash` disabled
     - all `bash` tool calls blocked
     - all `user_bash` commands blocked
     - visible error status until fixed/reloaded

---

## 15) Validation plan (acceptance tests)

## P0 (required)
1. New fingerprint prompts with exact 4 options.
2. `Allow Once` executes once and re-prompts next time.
3. `Allow for this session` suppresses prompts in same session only.
4. Session grants reset on new/switch/fork/restart (explicit `/resume` case included).
5. `Allow for this Project` persists and survives restart.
6. `Deny` blocks and does not persist.
7. Prompt cancel/timeout behaves exactly as `Deny`.
8. Input validation rejects invalid `target`/`command`/`cwd`/`timeout` deterministically.
9. `bash` direct `ssh/scp/sftp/sshpass/mosh` blocked.
10. `user_bash` (`!ssh`) blocked with expected result shape and exit code.
11. Matcher bypass variants blocked (`sudo -u`, `env -i`, `time -p`, `/usr/bin/ssh`, leading assignments, `exec ssh`).
12. Parser uncertainty/error causes block (fail closed) for both `tool_call` and `user_bash`.
13. non-SSH bash commands are unaffected.
14. no-UI + unknown fingerprint => denied.
15. no-UI + known global/trusted-project fingerprint => allowed.
16. no-UI ignores session grants.
17. untrusted project grants ignored (interactive and no-UI).
18. reusable-approval safety gate enforced: `Allow for this session` and `Allow for this Project` rejected for `cwd`/relative-path-sensitive commands.
19. trust bootstrap deny/cancel path: no execution, no trust write, no grant write.
20. policy parse/write failure on unapproved command => denied (fail closed).
21. secure persistence failure paths (owner/perms mismatch, symlink target, oversize/corrupt files, atomic write failure) deny and do not partially persist.
22. emergency startup fail-closed mode validated (fatal guard init => `ssh_bash` disabled + `bash`/`user_bash` blocked).
23. `/ssh-policy clear` behavior deterministic (confirm in UI for persistent scopes).
24. `/ssh-policy reload` behavior deterministic (session set preserved).
25. revoke prefix behavior: 0, 1, many matches deterministic.

## P1 (strongly recommended)
26. Fingerprint normalization equivalence tests (line endings/trim/trailing blank lines/target trim).
27. Fingerprint non-equivalence tests (different target/different command).
28. Truncation boundaries: exactly 50KB, exactly 2000 lines.
29. timeout and abort behavior deterministic.
30. non-zero remote exit returns stable error/result behavior.
31. audit records emitted for each decision type.

## P2 (nice-to-have)
32. extension interaction smoke tests (sandbox + plan-mode + bash override).
33. race test for concurrent same-fingerprint approvals.
34. project trust bootstrap flows in interactive/no-UI.

## Sign-off criteria
- all P0 pass
- P1 pass or explicitly accepted risk waivers
- no flaky tests across 3 consecutive runs

---

## Appendix A: Suggested implementation layout

```txt
src/
  index.ts
  policy/
    schema.ts
    store.ts
    trust.ts
    fingerprint.ts
  ssh/
    execute.ts
    matcher.ts
    validate.ts
  ui/
    prompt.ts
  commands/
    ssh-policy.ts
```

## Appendix B: Minimal pseudo-flow

```ts
on ssh_bash.execute(params, ctx):
  validate(params)
  fp = fingerprint(target, command)
  grants = resolveEffectiveGrants(ctx.hasUI)

  if grants.has(fp):
    return runSsh(params, decision="auto_allow_policy")

  if !ctx.hasUI:
    return deny("Not pre-approved and UI unavailable", decision="deny_no_ui")

  choice = prompt(Allow Once / Session / Project / Deny)

  switch choice:
    case once:
      return runSsh(params, decision="allow_once")
    case session:
      sessionSet.add(fp)
      return runSsh(params, decision="allow_session")
    case project:
      ensureProjectTrustedOrConfirm()
      persistProjectGrantOrDeny(fp)
      return runSsh(params, decision="allow_project")
    default:
      return deny("Blocked by user", decision="deny")
```
