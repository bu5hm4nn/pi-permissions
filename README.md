# pi-permissions

A pi extension that adds controlled permission workflows for remote SSH commands (`ssh_bash` tool) and optionally local bash commands, with per-command approvals and safe defaults.

## Features

- **`ssh_bash` tool** for remote command execution over SSH
- **Per-command approval workflows** with multiple grant scopes
- **Dual-domain permissions**: SSH (enabled by default) and Bash (disabled by default)
- **Blocks direct SSH-family commands** outside the `ssh_bash` tool
- **Fail-closed security model** for uncertain/unsafe cases

---

## Permission Domains

This extension supports two permission domains with independent configuration:

| Domain | Purpose | Default |
|--------|---------|---------|
| **SSH** | Controls `ssh_bash` tool approval prompts | Enabled |
| **Bash** | Controls local `bash` tool approval prompts | Disabled |

### SSH Domain

When enabled (default), the SSH domain:
- Prompts for approval when `ssh_bash` is invoked with a new command fingerprint
- Blocks direct `ssh`, `scp`, `sftp`, `sshpass`, and `mosh` commands via `bash` tool
- Stores grants per-session, per-project, or globally

### Bash Domain

When enabled, the Bash domain:
- Prompts for approval before executing local bash commands via the `bash` tool
- Analyzes commands to generate reusable patterns (e.g., `rm -rf <path>` becomes `rm -rf *`)
- Session-scoped grants only (no persistent storage in current version)

**Why disabled by default?** The Bash domain adds friction to every bash command. It's intended for high-security environments or when working on unfamiliar codebases. Most users should leave it disabled unless specifically needed.

---

## Configuration via `/permissions`

Run `/permissions` to open the permissions panel:

```
┌─ Permissions ───────────────────────┐
│                                     │
│  ☑ SSH permissions                  │
│  ☐ Bash permissions                 │
│                                     │
│  [Save]  [Cancel]                   │
└─────────────────────────────────────┘
```

Configuration is stored in:
- **Global**: `~/.pi/agent/permissions.json`
- **Project**: `.pi/permissions.json` (overrides global)

### Manual Configuration

You can also edit the JSON files directly:

```json
{
  "version": 1,
  "updatedAt": "2026-03-01T12:00:00.000Z",
  "permissions": {
    "ssh": { "enabled": true },
    "bash": { "enabled": false }
  }
}
```

---

## Approval Scopes

When prompted for a new command, you have four options:

| Option | Scope | Persistence | Best For |
|--------|-------|-------------|----------|
| **1. Allow Once** | Single execution | None | One-off commands |
| **2. Allow for this session** | Current session | Memory only | Repeated commands this session |
| **3. Allow for this Project** | Project scope | Disk (project) | Standard workflow commands |
| **4. Deny** | Block | None | Unwanted commands |

### How Scopes Work

- **Session grants** are cleared when you run `/new`, `/resume`, `/fork`, or restart pi
- **Project grants** persist to disk and survive restarts; require project trust confirmation on first use
- **Global grants** are stored in `~/.pi/agent/ssh-policy-global.json` and apply everywhere

### Effective Policy Resolution

The extension uses an additive model:
```
effective = union(global.grants, project.grants if trusted, session if interactive)
```

In no-UI mode (non-interactive), only persistent grants (global + trusted project) are honored.

---

## Quick Start

### Running the Extension

From this repo root:

```bash
cd ~/code/pi/pi-permissions
pi -e ./src/index.ts
```

### Using `ssh_bash`

Ask pi to run a remote command:

```
> Check disk usage on my server
```

Pi will use `ssh_bash` and you'll see an approval prompt:

```
Approve SSH command?

Target: user@server.example.com
Command: df -h

Patterns that will be approved:
  df -h

[1] Allow Once
[2] Allow for this session
[3] Allow for this Project
[4] Deny
```

### Project Installation

To auto-load in a project, create a local extension:

```bash
mkdir -p .pi/extensions
ln -sf ../../src/index.ts .pi/extensions/ssh-permission.ts
```

---

## Policy Commands

### `/ssh-policy` (Deprecated)

> **Note:** `/ssh-policy` is deprecated. Use `/permissions` for configuration.

The `/ssh-policy` command still works for grant management:

```bash
# List grants
/ssh-policy list                  # Show effective (combined) grants
/ssh-policy list session          # Show session grants only
/ssh-policy list project          # Show project grants only
/ssh-policy list global           # Show global grants only

# Clear grants
/ssh-policy clear session         # Clear session grants
/ssh-policy clear project         # Clear project grants (requires confirmation)
/ssh-policy clear global          # Clear global grants (requires confirmation)
/ssh-policy clear all             # Clear everything

# Revoke specific grant
/ssh-policy revoke session <prefix>   # Revoke by fingerprint prefix (8+ hex chars)
/ssh-policy revoke project <prefix>
/ssh-policy revoke global <prefix>

# Reload from disk
/ssh-policy reload                # Re-read policy files (keeps session grants)
```

---

## Example Workflows

### SSH: Approving a One-Time Command

```
User: Run `uptime` on my server user@prod-1

[Prompt: Approve SSH command?]
Target: user@prod-1
Command: uptime
→ Choose: 1. Allow Once

Output: 10:23:45 up 45 days, 2:31, 1 user, load average: 0.15, 0.10, 0.05
```

Next time the same command runs, you'll be prompted again.

### SSH: Approving for Session

```
User: Check kubernetes pods

[Prompt: Approve SSH command?]
Target: user@k8s-bastion
Command: kubectl get pods -A
→ Choose: 2. Allow for this session

# Now the same command won't prompt again this session
User: Check pods again
# Runs automatically (auto_allow_policy)
```

### SSH: Approving for Project

```
User: Deploy to staging

[Prompt: Approve SSH command?]
Target: deploy@staging
Command: ./deploy.sh
→ Choose: 3. Allow for this Project

[Prompt: Trust project for SSH policy?]
Project: /home/user/myproject
→ Confirm: Yes

# Grant persists to .pi/ssh-bash-permissions.json
# Next session in this project auto-approves
```

### Bash: Enabling and Using (Advanced)

```
# Enable bash permissions
/permissions
→ Check "Bash permissions"
→ Save

# Now bash commands prompt for approval
User: Clean build artifacts

[Prompt: Approve Bash command?]
Target: local
Command: rm -rf ./build
Patterns: rm -rf *
→ Choose: 2. Allow for this session

# Pattern "rm -rf *" now approved for session
User: Also clean dist folder
# Command: rm -rf ./dist
# Auto-approved because "rm -rf *" pattern matches
```

---

## Security Model

### Fail-Closed Behavior

The extension defaults to blocking when uncertain:

- **Parser uncertainty** → Block (can't determine command structure)
- **Policy read failure** → Block unapproved commands
- **Prompt cancelled/timeout** → Deny
- **Startup self-check failure** → Enter emergency fail-closed mode

### Direct SSH Blocking

These commands are blocked when invoked via `bash` tool:

- `ssh`, `scp`, `sftp`, `sshpass`, `mosh`
- Including wrapper invocations: `sudo ssh`, `env ssh`, `/usr/bin/ssh`

Users must use `ssh_bash` for remote command execution.

### Secure File I/O

Policy files are protected with:
- `0600` permissions (owner read/write only)
- Owner UID verification
- Symlink rejection
- Atomic writes (temp file + rename)
- Size limits (1MB max, 10K grants max)

---

## Migration Notes

### From v1 to v2 Policy Schema

The extension automatically migrates v1 policy files:
- Adds `domain: "ssh"` to existing grants
- Updates version number to 2
- Preserves all existing grant data

No manual migration required.

### From Central to Project-Local Storage

Project grants now store in `.pi/ssh-bash-permissions.json` within the project.
Legacy grants in `~/.pi/agent/ssh-policy-projects/<projectId>.json` are auto-migrated on first access.

---

## Project Structure

```
src/
  index.ts                    # Extension entry point
  policy/
    fingerprint.ts            # Command normalization and fingerprinting
    schema.ts                 # Policy file schemas
    store.ts                  # Secure policy storage
    trust.ts                  # Project trust registry
    command-patterns.ts       # Pattern analysis
  ssh/
    execute.ts                # SSH execution with streaming
    guard.ts                  # Tool call and user_bash guards
    matcher.ts                # Direct SSH-family detection
    validate.ts               # Input validation
  shell/
    analyzers/                # Command-specific analyzers
  ui/
    prompt.ts                 # Approval prompt UI
  commands/
    ssh-policy.ts             # /ssh-policy and /permissions commands
```

---

## Additional Documentation

- **Spec**: `docs/ssh-permission-extension-spec.md`
- **Examples**: `docs/examples.md`
- **Parser Design**: `docs/parser-refactor-phases-1-5.md`
- **Permissions Generalization**: `docs/permissions-generalization-plan.md`
- **Agent Notes**: `AGENTS.md`

---

## Notes

- This extension is security-sensitive; prefer small changes and re-review after edits
- See `AGENTS.md` for subagent workflow and handoff guidance
- Run tests with `npm test` before submitting changes
