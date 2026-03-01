# Subagent Review Results

Source: parallel `subagent` run with project agents (`spec-architect`, `security-reviewer`, `qa-validator`).

## spec-architect

- Exit code: 0
- Model: gpt-5.3-codex

1) **Overall verdict:** **FAIL** (confidence: **0.87**)

The spec is strong, but it is **not yet implementation-ready** due to a few behavior contradictions and security-critical ambiguities.

2) **Critical issues (must-fix)**

- **No-UI vs session grants is contradictory**  
  - **Refs:** §1.3, §3 (UX flow step 2), §8 (effective policy), §9.3, §15.10–11  
  - **Issue:** §3 implies session grants always execute; §1.3 says in no-UI only persistent approvals pass.  
  - **Change request:** Define explicit evaluation order for two modes:  
    - `interactiveEffective = session ∪ project ∪ global`  
    - `noUiEffective = project ∪ global` (session ignored)

- **“Project overrides” conflicts with union-only model**  
  - **Refs:** §1.5, §8  
  - **Issue:** “global defaults + project overrides” implies subtraction/precedence, but §8 defines only additive union.  
  - **Change request:** Either (A) rename to “project additions” everywhere, or (B) add `project.denies` (or override map) with precedence rules.

- **Project policy file path is ambiguous and unstable**  
  - **Refs:** §8 (File locations)  
  - **Issue:** `<cwd>/.pi/ssh-policy.json` is unclear (runtime cwd can change).  
  - **Change request:** Define deterministic project root resolution (e.g., git root fallback to startup cwd) and use that fixed root for the whole runtime.

- **Blocking scope and matcher are under-specified for a security boundary**  
  - **Refs:** §0.3, §2 (Security boundary), §11  
  - **Issue:** “Block SSH usage not through ssh_bash” conflicts with “block only direct commands,” and matcher rules are too vague (easy bypass variance).  
  - **Change request:** Align wording to “direct invocations only” (if intended), and define exact matcher contract (what counts as direct, delimiters, basename/path handling, sudo/env wrappers, multi-command lines).

- **`target` input is not constrained against SSH option injection**  
  - **Refs:** §3 (tool params), §10 (transport)  
  - **Issue:** `target` may start with `-` and be interpreted as ssh options.  
  - **Change request:** Validate `target` (reject leading `-`, control chars/newlines), and/or enforce `--` separator if supported.

3) **Important improvements (should-fix)**

- **`user_bash` interception return shape is ambiguous**  
  - **Refs:** §11.B  
  - **Change request:** Specify exact return payload: `return { result: { output, exitCode, cancelled, truncated } }`.

- **Remote wrapping/quoting algorithm is not concrete**  
  - **Refs:** §10  
  - **Change request:** Specify exact command construction and quoting function for `cwd` and `bash -lc` payload to avoid broken execution/injection.

- **Store schema invariants missing**  
  - **Refs:** §8  
  - **Change request:** Define dedupe/upsert by fingerprint, `updatedAt` update rules, and whether `source` is persisted or derived from file scope.

- **Revoke semantics by prefix are ambiguous**  
  - **Refs:** §12 (`revoke`)  
  - **Change request:** Define minimum prefix length, behavior on 0/multiple matches, and whether `session` scope is valid.

- **Failure behavior on policy write errors is undefined**  
  - **Refs:** §9.5–6, §13  
  - **Change request:** If user chose “Allow for this Project” and write fails, specify deterministic outcome (deny vs fallback prompt/allow-once).

4) **Nice-to-have improvements**

- Add acceptance tests for matcher edge cases (`; ssh`, absolute path `/usr/bin/ssh`, sudo/env wrappers, multiline).
- Add acceptance test for “session-approved command in no-UI mode” (expected deny/allow explicitly).
- Define `commandPreview` sanitization/truncation policy (length, redaction hints) and audit log rotation policy.

5) **Concise patch plan**

- Update §1/§3/§8/§9 with one canonical decision algorithm (interactive vs no-UI effective sets).
- Resolve §1.5 vs §8 by choosing additive-only model or adding deny/override schema.
- Replace `<cwd>` in §8 with explicit project-root discovery and fixed runtime binding.
- Rewrite §11 matcher spec with explicit lexical rules + examples + non-goals.
- Harden §3/§10 input validation and exact SSH argv/quoting contract.
- Clarify §12 command scope/error semantics and §13 write-failure behavior.
- Expand §15 with edge-case tests tied to above changes.

## security-reviewer

- Exit code: 0
- Model: gpt-5.3-codex

Reviewed: `docs/ssh-permission-extension-spec.md`

## 1) Risk summary (high/medium/low)

**High risk** overall.  
The spec has strong intent, but there are multiple practical bypass paths that can lead to:
- SSH execution outside `ssh_bash`
- Silent auto-allow in no-UI mode via policy abuse
- Potential **local** command execution through unsafe `target` handling

---

## 2) Top 5 attack paths

1. **Command matcher bypass in `bash` / `user_bash` guards** (High)  
   Pattern-based matching is easy to evade:
   - `true && /usr/bin/ssh user@h id`
   - `VAR=1 command ssh user@h id`
   - `\ssh user@h id`
   - multiline / control-operator forms  
   **Impact:** direct SSH runs without permission flow.

2. **`target` option injection in `ssh_bash`** (High)  
   `target` is free-form string. If it begins with `-o...`, SSH may interpret it as options (e.g., `ProxyCommand`) and run local commands.  
   **Impact:** local host command execution under agent user.

3. **Project policy poisoning + no-UI auto-allow** (High)  
   Policy path is in repo (`<cwd>/.pi/ssh-policy.json`). A malicious repo can preseed grants. In no-UI mode, those grants pass automatically.  
   **Impact:** silent policy evasion in CI/automation.

4. **Permission key omits `cwd`** (Medium/High)  
   Approved `target+command` can be replayed with different `cwd`, changing behavior materially.  
   **Impact:** overbroad approvals vs user intent.

5. **Guard coverage gaps / extension conflict fail-open behavior** (Medium/High)  
   Spec only blocks built-in `bash` and `!` `user_bash`. Other shell-capable tools (or hook conflicts) can bypass, and current text only says “emit diagnostics if inactive.”  
   **Impact:** enforcement can be bypassed without hard failure.

---

## 3) Required mitigations (must add)

1. **Harden SSH command detection (fail closed):**
   - Replace simple pattern matching with shell tokenization/AST-level command-word extraction.
   - Detect banned executables by basename (`ssh|scp|sftp|sshpass|mosh`) across command segments (`;`, `&&`, `||`, pipelines, newlines).
   - On parse uncertainty/error: **block** (not allow).

2. **Strictly validate `target` (no option injection):**
   - Reject leading `-`, whitespace/control chars, and shell metacharacters.
   - Prefer structured params (`host`, optional `user`, optional `port`) instead of free-form `target`.
   - Ensure args are constructed so destination cannot be interpreted as option flags.

3. **Fix fingerprint scope: include `cwd` or remove it from API:**
   - Add `cwdCanonical` to fingerprint material, **or**
   - disallow persisted grants when `cwd` is provided (Allow Once only).

4. **Lock down policy trust model:**
   - Do **not** auto-trust repo-stored project policy by default.
   - Require explicit project trust/bootstrap step before loading project grants.
   - In no-UI mode, disable untrusted project grants by default.

5. **Secure policy file I/O against tampering:**
   - Owner/perms checks (user-owned, `0600`), reject group/world writable.
   - Reject symlinks/hardlinks (`O_NOFOLLOW`), atomic write (`tmp + rename`).
   - Enforce max file size / max grants to prevent DoS.

6. **Fail closed on guard inactivity/conflict:**
   - If guard hooks are not active, extension should error out or disable execution paths—not just log diagnostics.

7. **Extend enforcement beyond built-in `bash` where possible:**
   - Add global execution-policy integration (all shell-like tools), or clearly declare hard limitation and require sandbox-level binary deny controls.

---

## 4) Recommended hardening (should add)

- **No-UI stricter default:** allow only global, user-owned trusted grants unless explicit `--allow-project-ssh-policy`.
- **Prompt hardening:** show full normalized `target`, `cwd`, and full command before approval; default selection = Deny.
- **Audit hardening:** secure audit file perms (`0600`), include policy source/trust state in each event.
- **Grant lifecycle controls:** optional TTL for session/project grants and easy expiration.
- **Optional host allowlist / denylist:** reduce blast radius of approved commands.

---

## 5) Test cases to validate mitigations

1. **Matcher bypass variants blocked**  
   Input: `true && /usr/bin/ssh user@h id` via `bash`  
   Expected: blocked with SSH-direct-use message.

2. **Wrapper prefix blocked**  
   Input: `VAR=1 command ssh user@h id`  
   Expected: blocked.

3. **Multiline/control operator blocked**  
   Input contains newline then `ssh ...`  
   Expected: blocked.

4. **Parse failure fails closed**  
   Input: syntactically broken shell string  
   Expected: blocked (not allowed).

5. **Target option injection rejected**  
   `target="-oProxyCommand=sh -c 'id' victim"`  
   Expected: validation error before execution.

6. **Invalid target chars rejected**  
   Leading dash, spaces, control chars, metacharacters  
   Expected: validation error.

7. **`cwd`-sensitive fingerprinting**  
   Approve command with `cwd=/safe`; rerun same command with `cwd=/root`  
   Expected: reprompt (different fingerprint) or blocked per policy.

8. **Untrusted project policy ignored in no-UI**  
   Repo contains preseeded `.pi/ssh-policy.json`  
   Expected: denied unless trust bootstrap explicitly enabled.

9. **Symlink policy write blocked**  
   `.pi/ssh-policy.json` symlink to another file  
   Expected: write denied, security error logged.

10. **Hook conflict fail-closed**  
    Simulate missing/inactive `tool_call` guard  
    Expected: extension startup fails or ssh features disabled.

11. **Non-bash tool path covered**  
    Run SSH via alternate shell-capable tool  
    Expected: blocked by global enforcement (or explicit documented limitation test).

12. **No-UI trusted grant path works**  
    Trusted persistent grant exists  
    Expected: executes without prompt; audit records `auto_allow_policy`.

## qa-validator

- Exit code: 0
- Model: gpt-5.3-codex

1) **Coverage score (0-100)**  
- **68/100**  
- Good baseline for happy paths; weak on deterministic edge cases, negative paths, and recovery/interaction behavior in `docs/ssh-permission-extension-spec.md`.

2) **Gaps by area**  
- **Permission semantics**
  - Missing explicit tests for **Deny** (non-persistent) and **prompt cancel/timeout => Deny**.
  - Session grant clearing on **session_start / switch / fork / restart** not validated.
- **Fingerprinting/identity**
  - No tests for normalization rules (CRLF/LF, trim, trailing blank lines, target trim).
  - No explicit test that **`cwd` does not affect fingerprint**.
- **SSH blocking matcher**
  - Only basic `ssh` block tested; no bypass/false-positive matrix (whitespace, env prefix, command chains, quoted text, similar names).
  - Exact “strict family only” behavior not validated deterministically.
- **Persistence + recovery**
  - Corrupt file test exists, but missing read/write permission failures, partial writes, reload recovery path.
  - `revoke` prefix edge cases (0 match / multiple match) not covered.
- **Execution robustness**
  - Missing deterministic non-zero exit behavior test.
  - Boundary tests for truncation thresholds (exact 50KB, exact 2000 lines) missing.
  - `cwd` quoting/injection safety not validated.
- **Management commands**
  - Test #15 is too broad; command-by-command assertions needed (default scope, confirmation behavior, output schema).
- **Security/observability**
  - No tests for audit log emission/fields.
  - No test ensuring persistent stores do **not** contain full command text (preview-only).
- **Compatibility/mode interactions**
  - No tests for plan/sandbox interactions or startup diagnostics when guards are inactive.

3) **Proposed additional tests (prioritized)**  
- **P0 (must-have)**
  - Deny decision blocks execution and re-prompts next identical call; no cache/store mutation.
  - UI cancel and UI timeout behave exactly as Deny.
  - Fingerprint normalization equivalence matrix + non-equivalence matrix; include `cwd`-invariance.
  - Session grant reset on session lifecycle events (`start/switch/fork/restart`).
  - No-UI mode: unknown denied; persistent known allowed; session-only grants not treated as persistent.
  - Matcher matrix for both `tool_call(bash)` and `user_bash`: block true positives + allow false positives.
  - Fail-closed on project/global policy read/write errors (including allow-project write failure).
  - `/ssh-policy revoke` prefix edge cases (none, unique, ambiguous) deterministic outputs.
  - Non-zero SSH exit returns stable, asserted error/result shape.
- **P1 (strongly recommended)**
  - Truncation boundary tests at exactly 50KB and 2000 lines; temp file path exists when truncated.
  - `cwd` wrapping safely quoted (no shell injection via cwd).
  - `/ssh-policy list` default scope = effective; output columns deterministic.
  - `/ssh-policy clear` confirmation required with UI; cancel leaves state unchanged.
  - Corrupt file -> visible error -> fix file -> `/ssh-policy reload` -> success path.
  - Audit log entries for all decisions (`allow_once/session/project/deny/auto_allow_policy/deny_no_ui`) with required fields.
- **P2 (nice-to-have/nightly)**
  - Extension interaction smoke tests (sandbox, plan-mode constraints, guard-inactive startup diagnostics).
  - Concurrent identical new requests race test (single prompt / no duplicate inconsistent writes).

4) **Minimal CI test matrix**  
- **Job A: Unit (fast, ubuntu-latest, node LTS)**
  - fingerprint normalization, matcher, schema parsing/unknown fields, commandPreview sanitation.
- **Job B: Integration UI mode (mock `ctx.hasUI=true`)**
  - approval flows, deny/cancel, session behavior, management commands with confirmation.
- **Job C: Integration headless mode (`ctx.hasUI=false`)**
  - persistent-only allow behavior, deterministic deny messages, no prompt paths.
- **Job D: Persistence/recovery**
  - global+project union, corrupt/read/write failures, reload recovery, revoke/clear edge cases.
- **Job E: Execution pipeline**
  - timeout, abort, non-zero exit, streaming/truncation boundaries (use deterministic fake `ssh` binary in PATH).  
- *(Optional nightly)* Real localhost `sshd` smoke test.

5) **Exit criteria for implementation sign-off**  
- All **P0** tests passing in CI; no skipped P0 cases.
- P1 suite passing or explicitly deferred with risk sign-off.
- Deterministic assertions for:
  - exact prompt labels,
  - block reason text,
  - no-UI deny message,
  - `user_bash` blocked exit code,
  - management command outputs.
- Coverage thresholds met:
  - policy/matcher/fingerprint modules: high branch coverage (target ≥90%).
- Flake check: full suite passes on at least 3 consecutive CI runs.
- Security checks pass:
  - no full command persisted in policy store,
  - audit log contains required fields for each decision path.
