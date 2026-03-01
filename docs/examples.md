# Permission Extension Examples

This document provides detailed examples of using the SSH and Bash permission domains.

## Table of Contents

1. [SSH Permission Workflows](#ssh-permission-workflows)
2. [Bash Permission Workflows](#bash-permission-workflows)
3. [Scope Comparison](#scope-comparison)
4. [Advanced Scenarios](#advanced-scenarios)
5. [Troubleshooting](#troubleshooting)

---

## SSH Permission Workflows

### Example 1: First-Time SSH Command

When you first ask pi to run a remote command:

```
User: Check if nginx is running on web-server

Pi: I'll check the nginx status for you.
```

The extension intercepts the `ssh_bash` call and shows:

```
┌─ Approve SSH command? ────────────────────────────────────────────┐
│                                                                   │
│  Target: deploy@web-server                                        │
│  Command: systemctl status nginx                                  │
│                                                                   │
│  Patterns that will be approved:                                  │
│    systemctl status nginx                                         │
│                                                                   │
│  [1] Allow Once                                                   │
│  [2] Allow for this session                                       │
│  [3] Allow for this Project                                       │
│  [4] Deny                                                         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Example 2: Reusable Pattern Approval

Commands are analyzed to extract reusable patterns. If you approve `kubectl get pods -n staging`, the pattern `kubectl get pods -n *` is what gets stored.

```
User: Show pods in production namespace

[Approval prompt]
Target: admin@k8s-bastion
Command: kubectl get pods -n production

Patterns that will be approved:
  kubectl get pods -n *

→ Choose: 2. Allow for this session
```

Later in the same session:

```
User: Now show pods in development

# No prompt! Pattern "kubectl get pods -n *" already approved
# Command "kubectl get pods -n development" matches
```

### Example 3: Project Trust Bootstrap

First time approving "Allow for this Project" in a new project:

```
User: Deploy the application

[Approval prompt]
Target: deploy@staging
Command: ./scripts/deploy.sh staging
→ Choose: 3. Allow for this Project

[Trust confirmation prompt]
┌─ Trust project for SSH policy? ───────────────────────────────────┐
│                                                                   │
│  Project: /home/user/my-webapp                                    │
│  Store: /home/user/my-webapp/.pi/ssh-bash-permissions.json        │
│                                                                   │
│  Allow this project to persist ssh approvals?                     │
│                                                                   │
│  [Yes]  [No]                                                      │
└───────────────────────────────────────────────────────────────────┘
```

After confirming, the grant is persisted and survives restarts.

### Example 4: Checking Approved Grants

```
/ssh-policy list effective

Scope: effective
Grants: 3
#  fingerprint     source   target              createdAt                preview
 1 a1b2c3d4e5f6  session  admin@k8s-bastion   -                        kubectl get pods -n *
 2 f7e8d9c0b1a2  project  deploy@staging      2026-03-01T10:00:00.000Z ./scripts/deploy.sh *
 3 1234567890ab  global   root@backup-server  2026-02-15T08:30:00.000Z rsync -avz * *
```

### Example 5: Revoking a Grant

```
# Find the fingerprint
/ssh-policy list project

Scope: project
Grants: 1
#  fingerprint     source   target           createdAt                preview
 1 f7e8d9c0b1a2  project  deploy@staging   2026-03-01T10:00:00.000Z ./scripts/deploy.sh *

# Revoke it (need at least 8 hex characters)
/ssh-policy revoke project f7e8d9c0

Revoked f7e8d9c0b1a2… from project
```

---

## Bash Permission Workflows

### Enabling Bash Permissions

First, enable the Bash domain via `/permissions`:

```
/permissions

┌─ Permissions ───────────────────────┐
│                                     │
│  ☑ SSH permissions                  │
│  ☐ Bash permissions   ← Toggle ON   │
│                                     │
│  [Save]  [Cancel]                   │
└─────────────────────────────────────┘
```

After saving with Bash enabled, local bash commands will prompt for approval.

### Example 6: First Bash Command Approval

```
User: Remove the build directory

Pi: I'll clean up the build artifacts.
```

```
┌─ Approve Bash command? ───────────────────────────────────────────┐
│                                                                   │
│  Target: local                                                    │
│  Command: rm -rf ./build                                          │
│                                                                   │
│  Patterns that will be approved:                                  │
│    rm -rf *                                                       │
│                                                                   │
│  [1] Allow Once                                                   │
│  [2] Allow for this session                                       │
│  [3] Allow for this Project  (unavailable for bash)               │
│  [4] Deny                                                         │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

**Note:** Bash permissions currently only support session-scoped grants. "Allow for this Project" is not available for local bash commands.

### Example 7: Pattern Matching in Action

After approving `rm -rf *`:

```
User: Also delete the dist folder
# Command: rm -rf ./dist
# Pattern rm -rf * already approved → auto-approved

User: Clean node_modules too
# Command: rm -rf ./node_modules
# Pattern rm -rf * still matches → auto-approved
```

### Example 8: Complex Command Patterns

Some commands generate multiple patterns:

```
User: Copy config and restart service

[Approval prompt]
Target: local
Command: cp ./config.json /etc/myapp/ && systemctl restart myapp

Patterns that will be approved:
  cp * /etc/myapp/*
  systemctl restart *

→ Choose: 2. Allow for this session
```

Both patterns are approved, and future commands matching either pattern auto-approve.

---

## Scope Comparison

### Session Scope

| Aspect | Behavior |
|--------|----------|
| Lifetime | Until `/new`, `/resume`, `/fork`, or restart |
| Storage | Memory only |
| Best for | Repeated operations in current task |
| Works in no-UI mode | No |

```
# Approve for session
→ Choose: 2. Allow for this session

# Grant in memory until session ends
/new  # Grant cleared
```

### Project Scope

| Aspect | Behavior |
|--------|----------|
| Lifetime | Permanent (until manually revoked) |
| Storage | `.pi/ssh-bash-permissions.json` in project |
| Best for | Standard project workflows |
| Works in no-UI mode | Yes (if project trusted) |

```
# Approve for project (first time triggers trust prompt)
→ Choose: 3. Allow for this Project

# Grant persists across sessions
# File: /path/to/project/.pi/ssh-bash-permissions.json
```

### Global Scope

| Aspect | Behavior |
|--------|----------|
| Lifetime | Permanent (until manually revoked) |
| Storage | `~/.pi/agent/ssh-policy-global.json` |
| Best for | Commands used across all projects |
| Works in no-UI mode | Yes |

Global grants are stored in the user's home directory and apply to all projects.

---

## Advanced Scenarios

### Scenario: CI/CD Pipeline (No-UI Mode)

In CI environments, there's no interactive UI. Only persistent grants work:

```bash
# Pre-approve commands for CI
# (Run this interactively before CI setup)

# Approve deployment command globally
ssh_bash deploy@prod "kubectl apply -f k8s/"
→ Choose: 3. Allow for this Project  # or save to global manually

# Now in CI (no-UI), the approved command auto-runs
# Unapproved commands fail with "deny_no_ui"
```

### Scenario: Unsafe Commands (cwd-sensitive)

Some commands are marked "reusable-unsafe" because they depend on the working directory:

```
User: Run the local install script

[Approval prompt]
Target: admin@server
Command: ./install.sh

Patterns that will be approved:
  (None - command is relative-path sensitive)

[1] Allow Once
[2] Allow for this session  ← Disabled (unsafe)
[3] Allow for this Project  ← Disabled (unsafe)
[4] Deny
```

These commands only allow "Allow Once" or "Deny" because the same command in a different directory could have completely different effects.

### Scenario: Pattern Analysis Incomplete

If the shell parser can't fully analyze a command:

```
[Approval prompt]
Target: admin@server
Command: eval "$DYNAMIC_CMD"

⚠ Pattern analysis incomplete - command structure uncertain

[1] Allow Once
[2] Allow for this session  ← Available but shows warning
[3] Allow for this Project  ← Available but shows warning
[4] Deny
```

### Scenario: Emergency Fail-Closed Mode

If the extension's startup self-check fails:

```
[Notification]
ssh-permission startup self-check failed: matcher self-check failed for command: ssh user@host

[Status bar shows]
ssh-permission: fail-closed
```

In this mode:
- `ssh_bash` tool is disabled
- All `bash` tool calls are blocked
- All user bash (`!`) commands are blocked

Resolution: Check extension installation and reload pi.

---

## Troubleshooting

### "Blocked by SSH permission policy" Error

**Cause:** Command fingerprint not in approved grants and prompt was denied or timed out.

**Solution:** Re-run the command and approve it, or check why it was denied.

### "Not pre-approved and UI unavailable"

**Cause:** Running in no-UI mode (CI/pipeline) with unapproved command.

**Solution:** Pre-approve the command interactively before running in no-UI mode.

### "Project trust denied/cancelled"

**Cause:** User cancelled the project trust confirmation prompt.

**Solution:** Re-run and confirm trust, or use "Allow Once" / "Allow for this session" instead.

### Direct SSH Commands Blocked

```
User: !ssh admin@server
Blocked: direct SSH-family commands are disabled. Use ssh_bash tool.
```

**Cause:** Direct SSH invocations are blocked by design.

**Solution:** Ask pi to run the command via `ssh_bash`:
```
User: Run "uptime" on admin@server
```

### Clearing All Approvals

To start fresh:

```
/ssh-policy clear all

Clear all policy entries?
[Yes] [No]

Cleared all policy scope
```

### Checking Extension Health

Look at the status bar:
- `ssh-permission: active` → Extension healthy
- `ssh-permission: fail-closed` → Extension in emergency mode

If in fail-closed mode, check logs and reload:
```
/ssh-policy reload
```

---

## Quick Reference

| Action | Command |
|--------|---------|
| Open permissions panel | `/permissions` |
| List all grants | `/ssh-policy list` |
| List session grants | `/ssh-policy list session` |
| Clear session grants | `/ssh-policy clear session` |
| Clear all grants | `/ssh-policy clear all` |
| Revoke specific grant | `/ssh-policy revoke <scope> <prefix>` |
| Reload policy files | `/ssh-policy reload` |

| File | Purpose |
|------|---------|
| `~/.pi/agent/permissions.json` | Global permission toggles |
| `.pi/permissions.json` | Project permission toggles |
| `~/.pi/agent/ssh-policy-global.json` | Global SSH grants |
| `.pi/ssh-bash-permissions.json` | Project SSH grants |
| `~/.pi/agent/ssh-policy-trust.json` | Trusted projects registry |
| `~/.pi/agent/ssh-policy-audit.log` | Audit log (JSONL) |
