/**
 * Integration tests for no-UI behavior and fail-closed semantics in bash domain.
 *
 * Tests cover:
 * 1. No-UI denial: when bash permissions enabled, no UI available, unapproved command → blocked
 * 2. Fail-closed on parser uncertainty: when command pattern analysis fails/incomplete → block if reusableUnsafe
 * 3. Approved commands pass through even without UI
 * 4. Guard health failure blocks all bash commands
 * 5. Audit logging in fail-closed scenarios
 */

import test from "node:test";
import assert from "node:assert/strict";
import { handleToolCallGuard, handleUserBashGuard, type GuardRuntime, type GuardResult } from "../src/ssh/guard.ts";
import { isDirectSshFamilyCommand } from "../src/shell/analyzers/direct-ssh.ts";

// =============================================================================
// Test Fixtures
// =============================================================================

interface AuditEntry {
	event: string;
	reason: string;
	commandPreview?: string;
	fingerprint?: string;
	patterns?: string[];
}

function createRuntime(
	overrides: Partial<GuardRuntime> & {
		auditLog?: AuditEntry[];
	} = {},
): GuardRuntime & { auditLog: AuditEntry[] } {
	const auditLog: AuditEntry[] = overrides.auditLog ?? [];
	return {
		guardHealthy: overrides.guardHealthy ?? true,
		matchDirectSsh: overrides.matchDirectSsh ?? isDirectSshFamilyCommand,
		bashPermissions: overrides.bashPermissions ?? { enabled: true },
		checkBashApproval: overrides.checkBashApproval,
		hasUI: overrides.hasUI ?? false,
		audit: async (entry: Record<string, unknown>) => {
			auditLog.push(entry as AuditEntry);
		},
		auditLog,
	};
}

// =============================================================================
// Section 1: No-UI Denial Tests
// =============================================================================

test("no-UI mode blocks unapproved bash commands with appropriate reason", async () => {
	const runtime = createRuntime({
		hasUI: false,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "rm -rf /tmp/test" } },
		runtime,
	);

	assert.deepEqual(result, {
		block: true,
		reason: "Bash command not approved. Enable UI for approval prompts.",
	});
});

test("no-UI mode logs audit entry when blocking unapproved command", async () => {
	const runtime = createRuntime({
		hasUI: false,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	});

	await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo dangerous" } },
		runtime,
	);

	assert.equal(runtime.auditLog.length, 1);
	assert.equal(runtime.auditLog[0].event, "tool_call_block");
	assert.equal(runtime.auditLog[0].reason, "bash_not_approved");
	assert.ok(runtime.auditLog[0].fingerprint, "Expected fingerprint in audit log");
	assert.ok(runtime.auditLog[0].commandPreview, "Expected commandPreview in audit log");
});

test("no-UI mode denies even simple safe-looking commands if not pre-approved", async () => {
	const runtime = createRuntime({
		hasUI: false,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	});

	// Even a simple "ls" should be blocked if not in approved set
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ls -la" } },
		runtime,
	);

	assert.deepEqual(result, {
		block: true,
		reason: "Bash command not approved. Enable UI for approval prompts.",
	});
});

test("no-UI mode allows pre-approved commands from global scope", async () => {
	const runtime = createRuntime({
		hasUI: false,
		checkBashApproval: async () => ({ approved: true, scope: "global" }),
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "npm test" } },
		runtime,
	);

	assert.equal(result, undefined, "Expected passthrough for globally approved command");
});

test("no-UI mode allows pre-approved commands from project scope", async () => {
	const runtime = createRuntime({
		hasUI: false,
		checkBashApproval: async () => ({ approved: true, scope: "project" }),
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "make build" } },
		runtime,
	);

	assert.equal(result, undefined, "Expected passthrough for project-approved command");
});

test("no-UI mode ignores session approvals (session scope treated as not approved)", async () => {
	// According to spec: "Session grants are ignored in no-UI mode"
	// The checkBashApproval callback should not return session grants in no-UI mode
	// This test verifies the guard's behavior when checkBashApproval correctly
	// returns approved: false in no-UI mode despite having session grants
	const runtime = createRuntime({
		hasUI: false,
		checkBashApproval: async () => {
			// Simulating: session grants exist but are ignored in no-UI mode
			return { approved: false, scope: "none" };
		},
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "git status" } },
		runtime,
	);

	assert.deepEqual(result, {
		block: true,
		reason: "Bash command not approved. Enable UI for approval prompts.",
	});
});

// =============================================================================
// Section 2: Fail-Closed on Missing Approval Callback
// =============================================================================

test("no approval callback with bash permissions enabled fails closed", async () => {
	const runtime = createRuntime({
		bashPermissions: { enabled: true },
		checkBashApproval: undefined, // No approval callback
		hasUI: true,
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo hello" } },
		runtime,
	);

	assert.deepEqual(result, {
		block: true,
		reason: "Bash command not approved. Enable UI for approval prompts.",
	});
});

test("no approval callback logs audit entry", async () => {
	const runtime = createRuntime({
		bashPermissions: { enabled: true },
		checkBashApproval: undefined, // No approval callback
		hasUI: true,
	});

	await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo test" } },
		runtime,
	);

	assert.equal(runtime.auditLog.length, 1);
	assert.equal(runtime.auditLog[0].event, "tool_call_block");
	assert.equal(runtime.auditLog[0].reason, "bash_no_approval_callback");
});

test("no approval callback blocks regardless of UI availability", async () => {
	// Even with UI, if there's no approval callback, we fail closed
	const runtimeWithUI = createRuntime({
		bashPermissions: { enabled: true },
		checkBashApproval: undefined,
		hasUI: true,
	});

	const runtimeNoUI = createRuntime({
		bashPermissions: { enabled: true },
		checkBashApproval: undefined,
		hasUI: false,
	});

	const resultWithUI = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "cat file.txt" } },
		runtimeWithUI,
	);

	const resultNoUI = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "cat file.txt" } },
		runtimeNoUI,
	);

	// Both should block
	assert.equal(resultWithUI?.block, true);
	assert.equal(resultNoUI?.block, true);
});

// =============================================================================
// Section 3: Guard Health Failure Tests
// =============================================================================

test("guard health failure blocks all bash commands", async () => {
	const runtime = createRuntime({
		guardHealthy: false,
		bashPermissions: { enabled: true },
		checkBashApproval: async () => ({ approved: true, scope: "global" }),
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ls" } },
		runtime,
	);

	assert.deepEqual(result, {
		block: true,
		reason: "SSH guard unhealthy: emergency fail-closed mode",
	});
});

test("guard health failure blocks even when bash permissions disabled", async () => {
	const runtime = createRuntime({
		guardHealthy: false,
		bashPermissions: { enabled: false },
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo safe" } },
		runtime,
	);

	assert.deepEqual(result, {
		block: true,
		reason: "SSH guard unhealthy: emergency fail-closed mode",
	});
});

test("guard health failure in user_bash returns proper result shape", async () => {
	const runtime = createRuntime({
		guardHealthy: false,
	});

	const result = await handleUserBashGuard({ command: "ls" }, runtime);

	assert.deepEqual(result, {
		result: {
			output: "Blocked: SSH guard unhealthy (emergency fail-closed mode).",
			exitCode: 126,
			cancelled: false,
			truncated: false,
		},
	});
});

// =============================================================================
// Section 4: Pattern Analysis Integration with No-UI
// =============================================================================

test("unapproved command with UI available returns promptNeeded with patterns", async () => {
	let capturedPatterns: string[] = [];
	const runtime = createRuntime({
		hasUI: true,
		checkBashApproval: async (_fp, _domain, patterns) => {
			capturedPatterns = patterns ?? [];
			return { approved: false, scope: "none" };
		},
	});

	const result = (await handleToolCallGuard(
		{ toolName: "bash", input: { command: "git status && npm test" } },
		runtime,
	)) as GuardResult;

	assert.equal(result.promptNeeded, true);
	assert.ok(result.fingerprint, "Expected fingerprint in result");
	assert.ok(result.patterns, "Expected patterns in result");
	assert.ok(result.patterns!.length > 0, "Expected at least one pattern");
	assert.ok(result.commandPreview, "Expected commandPreview in result");
});

test("pattern analysis returns complete flag for simple commands", async () => {
	const runtime = createRuntime({
		hasUI: true,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	});

	const result = (await handleToolCallGuard(
		{ toolName: "bash", input: { command: "npm install" } },
		runtime,
	)) as GuardResult;

	assert.equal(result.promptNeeded, true);
	assert.equal(result.patternAnalysisComplete, true);
});

test("pattern analysis returns complete for bare docker command", async () => {
	const runtime = createRuntime({
		hasUI: true,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	});

	// Command 'docker' without subcommand - now treated as complete with wildcard pattern
	// (shows help/usage, safe to approve generally)
	const result = (await handleToolCallGuard(
		{ toolName: "bash", input: { command: "docker" } },
		runtime,
	)) as GuardResult;

	assert.equal(result.promptNeeded, true);
	assert.equal(result.patternAnalysisComplete, true);
	assert.deepEqual(result.patterns, ["docker *"]);
});

// =============================================================================
// Section 5: Direct SSH Blocking Precedence
// =============================================================================

test("direct SSH blocking takes precedence over bash permissions check", async () => {
	let approvalCalled = false;
	const runtime = createRuntime({
		hasUI: true,
		bashPermissions: { enabled: true },
		checkBashApproval: async () => {
			approvalCalled = true;
			return { approved: true, scope: "global" };
		},
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ssh user@host" } },
		runtime,
	);

	assert.deepEqual(result, {
		block: true,
		reason: "Direct SSH-family commands are blocked. Use ssh_bash.",
	});
	assert.equal(approvalCalled, false, "Approval callback should not be called for direct SSH");
});

test("direct SSH blocking logs audit before bash permission check", async () => {
	const runtime = createRuntime({
		hasUI: true,
		bashPermissions: { enabled: true },
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	});

	await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ssh user@host" } },
		runtime,
	);

	assert.equal(runtime.auditLog.length, 1);
	assert.equal(runtime.auditLog[0].event, "tool_call_block");
	assert.equal(runtime.auditLog[0].reason, "direct_ssh_block");
});

// =============================================================================
// Section 6: Matcher Exception Handling (Fail-Closed)
// =============================================================================

test("matcher exception triggers fail-closed block", async () => {
	const runtime = createRuntime({
		matchDirectSsh: () => {
			throw new Error("Parser crashed");
		},
		bashPermissions: { enabled: false },
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo hello" } },
		runtime,
	);

	// Should block because matcher exception = assume dangerous
	assert.deepEqual(result, {
		block: true,
		reason: "Direct SSH-family commands are blocked. Use ssh_bash.",
	});
});

test("user_bash matcher exception triggers fail-closed", async () => {
	const runtime = createRuntime({
		matchDirectSsh: () => {
			throw new Error("Parser error");
		},
	});

	const result = await handleUserBashGuard({ command: "echo test" }, runtime);

	assert.equal(result?.result?.exitCode, 126);
	assert.match(result?.result?.output || "", /direct SSH-family commands are disabled/i);
});

// =============================================================================
// Section 7: Passthrough Cases (Bash Permissions Disabled)
// =============================================================================

test("bash permissions disabled allows all non-SSH commands", async () => {
	const runtime = createRuntime({
		bashPermissions: { enabled: false },
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "rm -rf /" } },
		runtime,
	);

	assert.equal(result, undefined, "Expected passthrough when bash permissions disabled");
});

test("bash permissions disabled still blocks direct SSH", async () => {
	const runtime = createRuntime({
		bashPermissions: { enabled: false },
	});

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ssh root@server" } },
		runtime,
	);

	assert.deepEqual(result, {
		block: true,
		reason: "Direct SSH-family commands are blocked. Use ssh_bash.",
	});
});

// =============================================================================
// Section 8: Non-Bash Tools Passthrough
// =============================================================================

test("non-bash tools pass through even when guard unhealthy", async () => {
	const runtime = createRuntime({
		guardHealthy: false,
	});

	const result = await handleToolCallGuard(
		{ toolName: "read", input: { path: "/etc/passwd" } },
		runtime,
	);

	assert.equal(result, undefined, "Non-bash tools should pass through");
});

test("non-bash tools pass through with bash permissions enabled", async () => {
	const runtime = createRuntime({
		bashPermissions: { enabled: true },
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	});

	const result = await handleToolCallGuard(
		{ toolName: "write", input: { path: "/tmp/test", content: "data" } },
		runtime,
	);

	assert.equal(result, undefined, "Non-bash tools should not be subject to bash permissions");
});

// =============================================================================
// Section 9: Approval Scopes Correctly Passed Through
// =============================================================================

test("approval check receives fingerprint and domain", async () => {
	let capturedFingerprint = "";
	let capturedDomain = "";
	const runtime = createRuntime({
		hasUI: false,
		checkBashApproval: async (fp, domain) => {
			capturedFingerprint = fp;
			capturedDomain = domain;
			return { approved: true, scope: "global" };
		},
	});

	await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo test" } },
		runtime,
	);

	assert.ok(capturedFingerprint.length === 64, "Expected SHA-256 hex fingerprint");
	assert.equal(capturedDomain, "bash");
});

test("approval check receives extracted patterns", async () => {
	let capturedPatterns: string[] = [];
	const runtime = createRuntime({
		hasUI: true,
		checkBashApproval: async (_fp, _domain, patterns) => {
			capturedPatterns = patterns ?? [];
			return { approved: false, scope: "none" };
		},
	});

	await handleToolCallGuard(
		{ toolName: "bash", input: { command: "docker run alpine" } },
		runtime,
	);

	assert.ok(capturedPatterns.length > 0, "Expected patterns to be extracted and passed");
	assert.ok(capturedPatterns.some((p) => p.includes("docker")), "Expected docker pattern");
});
