import test from "node:test";
import assert from "node:assert/strict";
import { isDirectSshFamilyCommand } from "../src/ssh/matcher.ts";

// =============================================================================
// Test: isDirectSshFamilyCommandDetailed export existence
// Uses dynamic import + namespace to detect if export exists
// =============================================================================

test("matcher module exports isDirectSshFamilyCommandDetailed for detailed results", async () => {
	// RED: This test should FAIL because isDirectSshFamilyCommandDetailed is not exported
	// The function should return { blocked: boolean; reason?: 'ssh_detected' | 'parse_failure' | 'uncertain' }
	
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	// Check if the detailed version is exported
	assert.equal(
		typeof matcherModule.isDirectSshFamilyCommandDetailed,
		"function",
		"Expected isDirectSshFamilyCommandDetailed to be exported as a function",
	);
	
	// Check the result shape for a clean command
	const cleanResult = matcherModule.isDirectSshFamilyCommandDetailed("echo ok");
	assert.equal(typeof cleanResult, "object", "Expected result to be an object");
	assert.equal("blocked" in cleanResult, true, "Expected 'blocked' property in result");
	assert.equal("reason" in cleanResult, true, "Expected 'reason' property in result");
	
	// Clean commands should return { blocked: false, reason: undefined }
	assert.equal(cleanResult.blocked, false);
	assert.equal(cleanResult.reason, undefined);
});

// =============================================================================
// Test: Detailed matcher returns correct reason for SSH detection
// =============================================================================

test("detailed matcher returns ssh_detected for direct SSH commands", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	if (typeof matcherModule.isDirectSshFamilyCommandDetailed !== "function") {
		throw new Error("isDirectSshFamilyCommandDetailed not exported - TEST RED");
	}
	
	const sshCommands = [
		"ssh user@host",
		"\\ssh user@host",
		"sudo -- ssh user@host",
		"\\sudo -- \\ssh user@host",
		"scp file user@host:/tmp",
		"sftp user@host",
		"mosh user@host",
		"sshpass -p secret ssh user@host",
	];
	
	for (const cmd of sshCommands) {
		const result = matcherModule.isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, true, `Expected '${cmd}' to be blocked`);
		assert.equal(result.reason, "ssh_detected", `Expected reason='ssh_detected' for '${cmd}', got ${result.reason}`);
	}
});

// =============================================================================
// Test: Detailed matcher returns correct reason for parse failures
// =============================================================================

test("detailed matcher returns parse_failure for broken shell syntax", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	if (typeof matcherModule.isDirectSshFamilyCommandDetailed !== "function") {
		throw new Error("isDirectSshFamilyCommandDetailed not exported - TEST RED");
	}
	
	const parseFailureCommands = [
		"echo 'unterminated",
		"echo ok &&",
	];
	
	for (const cmd of parseFailureCommands) {
		const result = matcherModule.isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, true, `Expected parse failure command '${cmd}' to be blocked`);
		assert.equal(result.reason, "parse_failure", `Expected reason='parse_failure' for '${cmd}', got ${result.reason}`);
	}
});

// =============================================================================
// Test: Detailed matcher returns correct reason for uncertain constructs
// =============================================================================

test("detailed matcher returns uncertain for AST-walk uncertainty (function definitions)", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	if (typeof matcherModule.isDirectSshFamilyCommandDetailed !== "function") {
		throw new Error("isDirectSshFamilyCommandDetailed not exported - TEST RED");
	}
	
	// Function definitions are parsed successfully but AST walk reports uncertainty
	const astUncertainCommands = [
		"f(){ echo hi; }; f",
	];
	
	for (const cmd of astUncertainCommands) {
		const result = matcherModule.isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, true, `Expected uncertain command '${cmd}' to be blocked`);
		assert.equal(result.reason, "uncertain", `Expected reason='uncertain' for '${cmd}', got ${result.reason}`);
	}
});

test("detailed matcher blocks parser-uncertain constructs without SSH (fail-closed)", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");

	if (typeof matcherModule.isDirectSshFamilyCommandDetailed !== "function") {
		throw new Error("isDirectSshFamilyCommandDetailed not exported - TEST RED");
	}

	// Process substitution can't be parsed by the AST parser (parser uncertainty).
	// FAIL-CLOSED: Must block with parse_failure since we can't confirm no SSH.
	const parserUncertainCommands = [
		"cat <(echo hello)",
	];

	for (const cmd of parserUncertainCommands) {
		const result = matcherModule.isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, true, `Expected parser-uncertain command '${cmd}' without SSH to be blocked (fail-closed)`);
		assert.equal(result.reason, "parse_failure", `Expected reason='parse_failure' for '${cmd}', got ${result.reason}`);
	}
});

// =============================================================================
// Test: Clean commands return blocked=false with reason=undefined
// =============================================================================

test("detailed matcher returns blocked=false with reason=undefined for clean commands", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	if (typeof matcherModule.isDirectSshFamilyCommandDetailed !== "function") {
		throw new Error("isDirectSshFamilyCommandDetailed not exported - TEST RED");
	}
	
	const cleanCommands = [
		"echo ok",
		"FOO=bar",
		"echo hi > out.txt",
		"ls -la",
		"cat /etc/hosts",
	];
	
	for (const cmd of cleanCommands) {
		const result = matcherModule.isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, false, `Expected clean command '${cmd}' to not be blocked`);
		assert.equal(result.reason, undefined, `Expected reason=undefined for '${cmd}', got ${result.reason}`);
	}
});

// =============================================================================
// Existing tests for isDirectSshFamilyCommand (boolean version)
// =============================================================================

test("allows regular shell commands", () => {
	assert.equal(isDirectSshFamilyCommand("echo ok"), false);
	assert.equal(isDirectSshFamilyCommand("echo hi && cat /etc/hosts"), false);
	assert.equal(isDirectSshFamilyCommand("FOO=bar"), false);
});

test("blocks direct ssh-family commands", () => {
	assert.equal(isDirectSshFamilyCommand("ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("scp file user@host:/tmp"), true);
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

test("blocks parser-uncertain python heredoc without SSH (fail-closed for parse_failure)", () => {
	const script = String.raw`python3 - <<'PY'
from pathlib import Path
files = [
  'README.md',
  '.claude/skills/healthcheck/SKILL.md',
]
print('\n'.join(files))
PY`;
	// FAIL-CLOSED: Parser-uncertain heredocs without SSH are blocked (can't confirm no SSH)
	assert.equal(isDirectSshFamilyCommand(script), true);
});

test("blocks parser-uncertain python heredoc refactor script without SSH (fail-closed for parse_failure)", () => {
	const script = String.raw`python3 - <<'PY'
 from pathlib import Path

 files = [
 'AGENTS.md','CONTRIBUTING.md','README.md','.pi/sandbox.json',
 'hosts/edge-node-a.md','hosts/edge-node-b.md',
 'services/proxy.md','services/agent.md','services/alerts.md','services/mail.md','services/metrics.md','services/backup.md','services/scheduler.md','services/reports.md','services/updates.md','services/security/README.md','services/uptime/README.md','services/uptime/monitors.json'
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
	// FAIL-CLOSED: Parser-uncertain heredocs without SSH are blocked (can't confirm no SSH)
	assert.equal(isDirectSshFamilyCommand(script), true);
});

test("blocks parser-uncertain multiline loop+array perl script without SSH (fail-closed for parse_failure)", () => {
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
	// FAIL-CLOSED: Parser-uncertain cases without SSH must still be blocked
	assert.equal(isDirectSshFamilyCommand(script), true);
});

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