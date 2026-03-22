import test from "node:test";
import assert from "node:assert/strict";
import { isDirectSshFamilyCommand } from "../src/ssh/matcher.ts";

test("allows regular shell commands", () => {
	assert.equal(isDirectSshFamilyCommand("echo ok"), false);
	assert.equal(isDirectSshFamilyCommand("echo hi && cat /etc/hosts"), false);
	assert.equal(isDirectSshFamilyCommand("FOO=bar"), false);
});

test("blocks direct ssh-family commands (except SCP which passes through)", () => {
	assert.equal(isDirectSshFamilyCommand("ssh user@host"), true);
	// SCP passes through to bash permissions - not blocked by SSH matcher
	assert.equal(isDirectSshFamilyCommand("scp file user@host:/tmp"), false);
	assert.equal(isDirectSshFamilyCommand("sftp user@host"), true);
	assert.equal(isDirectSshFamilyCommand("mosh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("sshpass -p secret ssh user@host"), true);
});

test("blocks ssh-family commands through wrappers", () => {
	assert.equal(isDirectSshFamilyCommand("sudo -- ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("env FOO=bar ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("command ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("nohup ssh user@host &"), true);
});

// Parser-uncertain commands WITHOUT SSH should pass through (not fake "SSH blocked" error)
// They will then flow to bash permissions logic which will either:
// - Pass through (if bash permissions disabled)
// - Prompt for approval (if bash permissions enabled + UI available)
test("allows parser-uncertain python heredoc without SSH", () => {
	const script = String.raw`python3 - <<'PY'
from pathlib import Path
files = [
  'README.md',
  '.claude/skills/healthcheck/SKILL.md',
]
print('\n'.join(files))
PY`;
	assert.equal(isDirectSshFamilyCommand(script), false);
});

test("allows parser-uncertain python heredoc refactor script without SSH", () => {
	const script = String.raw`python3 - <<'PY'
 from pathlib import Path

 files = [
 'AGENTS.md','CONTRIBUTING.md','README.md','.pi/sandbox.json',
 'hosts/edge-node-a.md','hosts/edge-node-b.md',
 'services/proxy.md','services/agent.md','services/alerts.md','services/mail.md','services/metrics.md','services/backup.md','services/
 scheduler.md','services/reports.md','services/updates.md','services/security/README.md','services/uptime/README.md','services/uptime/mo
 nitors.json',
 'runbooks/post-install.md','tasks/setup-metrics.md',
 'plans/20260222-uptime.md','plans/20260222-scheduler.md',
 '.claude/skills/healthcheck/SKILL.md','.claude/skills/deploy-security-stack/SKILL.md',
 '.credentials'
 ]

 # Ordered replacements: specific -> general
 replacements = [
     ('grafana.oldcorp.internal', 'grafana.newcorp.internal'),
     ('kibana.oldcorp.internal', 'kibana.newcorp.internal'),
     ('oldcorp-alerts', 'newcorp-alerts'),
     ('oldcorp-updates', 'newcorp-updates'),
     ('oldcorp Infrastructure', 'newcorp Infrastructure'),
     ('/devops/oldcorp/', '/devops/newcorp/'),
     ('oldcorp.internal', 'newcorp.internal'),
     ('oldcorp.vpn', 'newcorp.vpn'),
 ]

 changed = []
 for rel in files:
     p = Path(rel)
     text = p.read_text()
     new = text
     for old, newv in replacements:
         new = new.replace(old, newv)

     # Skills requested "oldcorp -> newcorp" in title/description/path references
     if rel in {'.claude/skills/healthcheck/SKILL.md', '.claude/skills/deploy-security-stack/SKILL.md'}:
         new = new.replace('oldcorp', 'newcorp').replace('Oldcorp', 'Newcorp')

     if new != text:
         p.write_text(new)
         changed.append(rel)

 print('\n'.join(changed))
 PY`;
	assert.equal(isDirectSshFamilyCommand(script), false);
});

test("allows parser-uncertain multiline loop+array perl script without SSH", () => {
	const script = String.raw`
set -e
files=(
AGENTS.md CLAUDE.md README.md .pi/sandbox.json
hosts/edge-node-a.md hosts/edge-node-b.md
services/proxy.md services/agent.md services/alerts.md services/mail.md services/metrics.md services/backup.md services/scheduler.md
services/reports.md services/updates.md services/security/README.md services/uptime/README.md services/uptime/monitors.json
runbooks/post-install.md tasks/setup-metrics.md
plans/20260222-uptime.md plans/20260222-scheduler.md
.credentials
)
for f in "\${files[@]}"; do
  perl -pi -e "s/grafana\.oldcorp\.internal/grafana.newcorp.internal/g; s/kibana\.oldcorp\.internal/kibana.newcorp.internal/g; s/oldcorp-alerts/newcorp-alerts/g;
s/oldcorp-updates/newcorp-updates/g; s/oldcorp Infrastructure/newcorp Infrastructure/g; s#/devops/oldcorp/#/devops/newcorp/#g;
s/oldcorp\.internal/newcorp.internal/g; s/oldcorp\.vpn/newcorp.vpn/g" "$f"
done

# skills: replace oldcorp -> newcorp in title/description/path references
perl -pi -e 's/oldcorp/newcorp/g; s/Oldcorp/Newcorp/g' .claude/skills/healthcheck/SKILL.md .claude/skills/deploy-security-stack/SKILL.md

echo done
`;
	assert.equal(isDirectSshFamilyCommand(script), false);
});

// Broken shell (parse failure) should also pass through to bash permissions logic,
// not block with fake "SSH blocked" error. The user will be prompted if UI available.
test("blocks broken shell (parse failure) - fail-closed by default", () => {
	// Parse failures without SSH detected are blocked (fail-closed)
	assert.equal(isDirectSshFamilyCommand("echo 'unterminated"), true);
	assert.equal(isDirectSshFamilyCommand("echo ok &&"), true);
});

test("fail-closed for advanced/uncertain constructs containing ssh", () => {
	assert.equal(isDirectSshFamilyCommand("cat <(ssh user@host)"), true);
});

test("fail-closed when ssh appears inside function definition/invocation", () => {
	assert.equal(isDirectSshFamilyCommand("f(){ ssh user@host; }; f"), true);
});

