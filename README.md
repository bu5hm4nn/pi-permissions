# pi-ssh-permission-extension

A pi extension that adds a controlled `ssh_bash` tool with per-command approvals, and blocks direct SSH-family usage outside that tool.

## What this project contains

- **Implementation**: `src/`
- **Primary spec**: `docs/ssh-permission-extension-spec.md`
- **Review logs**:
  - `docs/subagent-review-results.md`
  - `docs/subagent-rereview-results.md`
- **Agent handoff notes**: `AGENTS.md`

## Core behavior

1. Adds `ssh_bash` tool (target + remote command execution).
2. Approval prompt for new command fingerprints:
   - Allow Once
   - Allow for this session
   - Allow for this Project
   - Deny
3. Blocks direct SSH-family commands outside the tool:
   - `ssh`, `scp`, `sftp`, `sshpass`, `mosh`
4. Uses fail-closed behavior for uncertain/unsafe cases.

---

## Run locally (quick start)

From this repo root:

```bash
cd ~/code/pi/pi-ssh-permission-extension
pi -e ./src/index.ts
```

If you prefer one-shot prompt mode while loading the extension:

```bash
cd ~/code/pi/pi-ssh-permission-extension
pi -e ./src/index.ts -p "Check extension is loaded and describe available SSH policy commands"
```

---

## Optional: install as project-local extension

To auto-load in this repo, copy/link the extension into `.pi/extensions/` (project-local pi extension discovery path):

```bash
mkdir -p .pi/extensions
ln -sf ../../src/index.ts .pi/extensions/ssh-permission.ts
```

Then run pi normally in this repo:

```bash
pi
```

---

## Manual smoke tests

Start pi with the extension:

```bash
pi -e ./src/index.ts
```

Then test these scenarios:

1. **Tool presence**
   - Ask pi to use `ssh_bash` for a harmless remote command.

2. **Approval flow**
   - First new command should prompt approval options.
   - Re-running after “Allow Once” should prompt again.

3. **Direct SSH blocking**
   - Ask pi to run `bash` command with `ssh ...` -> should be blocked.
   - Run interactive `!ssh ...` -> should be blocked.

4. **Policy commands**
   - `/ssh-policy list`
   - `/ssh-policy clear session`
   - `/ssh-policy reload`

5. **Timeout behavior**
   - Trigger a long-running remote command with timeout and verify error semantics.

---

## Notes

- This extension is security-sensitive; prefer small changes and re-review after edits.
- See `AGENTS.md` for subagent workflow and handoff guidance.
