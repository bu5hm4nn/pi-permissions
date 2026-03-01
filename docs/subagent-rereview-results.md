# Subagent Re-Review Results

## spec-architect

- Exit code: 0

**FAIL** (confidence: **0.82**)

Top remaining blockers:

1. **Guard matcher still has bypass-critical ambiguity**  
   - **Refs:** `§11.A`, `§11.B`  
   - The matcher contract omits command-list/background operator handling (notably single `&`) and does not define wrapper option parsing (`env -i`, `time -p`, `sudo -u`, etc.).  
   - **Must-fix:** make tokenization/operator handling fully explicit (quote-aware), include `&`, and define wrapper parsing rules with `--` semantics.

2. **Project trust registry is not implementation-defined enough**  
   - **Refs:** `§8` (trust path/model), `§13` (secure file IO)  
   - Trust file exists (`ssh-policy-trust.json`) but has no schema, no canonical trust key format, and no dedupe/update invariants.  
   - **Must-fix:** add a v1 trust JSON schema + canonical project identity rule (e.g., `realpath(projectRoot)`), plus mutation invariants.

3. **“Fail closed” on guard-init failure is currently inconsistent with objective**  
   - **Refs:** `§0` objective #3, `§11`, `§14` (guard health checks)  
   - Current text says on fatal guard init failure, disable `ssh_bash`; that does not guarantee direct SSH via `bash`/`user_bash` is blocked.  
   - **Must-fix:** require hard startup failure **or** hard-block all `bash`/`user_bash` executions until guards are healthy.

## security-reviewer

- Exit code: 0

**Risk level: HIGH**

**Must-fix items**

1. **Command matcher is bypassable with wrapper flags/variants (policy evasion).**  
   - **Attack:** `sudo -u root ssh ...`, `time -p ssh ...`, `env -i ssh ...`, `nice ssh ...` can evade a “skip wrapper word then take next token” matcher.  
   - **Must-fix spec change:** Require AST-based shell parsing and recursive wrapper unwrapping **with option handling**; if head command cannot be resolved with certainty, block (fail closed).

2. **Project policy store is tamperable (persistence abuse), especially dangerous in no-UI mode.**  
   - **Attack:** In a previously trusted project, modifying `<projectRoot>/.pi/ssh-policy.json` can pre-seed auto-allow fingerprints, which execute without prompt in no-UI.  
   - **Must-fix spec change:** Do **not** trust repo-local policy as authoritative. Store project grants in a user-owned path outside repo (keyed by canonical project root), or cryptographically bind entries to local user secret. Also validate ownership/perms on read.

3. **Fingerprint omits `cwd`, enabling approval replay in different directories.**  
   - **Attack:** Approve `command="./deploy.sh"` once; later run same command with different `cwd` pointing to attacker-controlled script, auto-allowed by same fingerprint.  
   - **Must-fix spec change:** Include canonical `cwd` (or explicit null marker) in fingerprint key material, or disallow persisted approvals for relative-command cases.

4. **Startup/guard failure handling can be fail-open for non-`ssh_bash` paths.**  
   - **Attack:** If matcher/guard init fails and only `ssh_bash` is disabled, direct `bash`/`user_bash` SSH may still run.  
   - **Must-fix spec change:** On guard init failure, enforce global deny for SSH-family commands in both `tool_call` and `user_bash` (or fail extension load entirely).

## qa-validator

- Exit code: 0

- **Updated coverage score:** **92/100**

- **P0 gaps (remaining):**
  - Missing **input validation negative/boundary tests** for `ssh_bash` (`target`, `command`, `cwd`, `timeout`) with deterministic reject behavior.
  - Missing **fail-closed parser-error tests** for SSH matcher in both `tool_call:bash` and `user_bash` (e.g., malformed shell input must block).
  - Missing **bypass-resistance tests** for direct-command matcher variants (`sudo ssh`, `env ... ssh`, `command ssh`, `/usr/bin/ssh`, leading assignments).
  - Missing explicit **mode/trust gating tests**: untrusted project grants ignored (including no-UI), and session grants ignored in no-UI.
  - Missing explicit lifecycle test for **`/resume` clearing session grants** (called out in frozen policy).
  - Missing required acceptance tests for **`/ssh-policy clear`** and **`/ssh-policy reload`** deterministic behavior (interactive confirmation vs no-UI, reload preserving session set).
