# E2E Test Report

Date: 2026-02-26
Repo: `~/code/pi/pi-permissions`
Extension entry: `src/index.ts`
Mode used: `pi --mode json -e ./src/index.ts --no-session`

## Test 1 — Unknown `ssh_bash` command in no-UI mode is denied
Prompt: call `ssh_bash(target=localhost, command="echo hello")`

Observed:
- Tool executed: `ssh_bash`
- Tool text: `Blocked by SSH permission policy.`
- Details: `decision=deny_no_ui`, `decisionScope=none`

Result: ✅ PASS

## Test 2 — Direct SSH via `bash` is blocked
Prompt: call `bash("ssh localhost 'echo hi'")`

Observed:
- Tool executed: `bash`
- Tool error text: `Direct SSH-family commands are blocked. Use ssh_bash.`

Result: ✅ PASS

## Test 3 — Non-SSH bash command still works
Prompt: call `bash("echo E2E_OK")`

Observed:
- Tool executed: `bash`
- Output: `E2E_OK`

Result: ✅ PASS

## Test 4 — Global policy auto-allow path
Setup:
- Created `~/.pi/agent/ssh-policy-global.json` with matching fingerprint for `target=localhost`, `command="echo hello"`

Prompt: call `ssh_bash(target=localhost, command="echo hello")`

Observed:
- Tool executed: `ssh_bash`
- Details: `decision=auto_allow_policy`, `decisionScope=global`
- SSH execution attempted; environment returned host verification failure and exit code `255`

Result: ✅ PASS (policy path), with expected runtime SSH failure due local host setup

## Notes / finding
- In tool result events, `ssh_bash` responses with blocked/non-zero outcomes appeared with `isError=false` in JSON message records, even when details indicate denied/non-zero exit.
- This may be a tool-result-shape/runtime behavior mismatch worth investigating separately.

## Overall
Core E2E behavior validated for:
- policy denial in no-UI,
- direct SSH blocking,
- normal bash unaffected,
- global auto-allow policy path.
