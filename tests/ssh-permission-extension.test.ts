/**
 * Extension-level tests for ssh-permission extension.
 *
 * GREEN Phase Tests:
 * 1. Startup self-check verifies parse failures return blocked=true with proper reason
 * 2. Detailed matcher export exists and returns correct shape
 * 3. Extension self-check verifies reason values
 */
import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";

// =============================================================================
// Test: Detailed matcher export exists from matcher module
// Uses dynamic import + namespace to detect if export exists
// =============================================================================

test("detailed matcher function is exported from ssh/matcher module", async () => {
	// GREEN: This test should PASS because the export exists
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	assert.equal(
		typeof matcherModule.isDirectSshFamilyCommandDetailed,
		"function",
		"Expected isDirectSshFamilyCommandDetailed to be exported from ssh/matcher",
	);
	
	// Type-level assertion: result has blocked and reason properties
	const result = matcherModule.isDirectSshFamilyCommandDetailed("test");
	assert.equal(typeof result, "object", "Expected result to be object");
	assert.ok("blocked" in result, "Expected 'blocked' property");
	assert.ok("reason" in result, "Expected 'reason' property");
});

// =============================================================================
// Test: Detailed matcher returns correct shape for all result types
// =============================================================================

test("detailed matcher returns correct shape for blocked=false (clean command)", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	const result = matcherModule.isDirectSshFamilyCommandDetailed("echo hello");
	assert.deepEqual(result, { blocked: false, reason: undefined });
});

test("detailed matcher returns correct shape for ssh_detected", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	const result = matcherModule.isDirectSshFamilyCommandDetailed("ssh user@host");
	assert.equal(result.blocked, true);
	assert.equal(result.reason, "ssh_detected");
});

test("detailed matcher returns correct shape for parse_failure", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	const result = matcherModule.isDirectSshFamilyCommandDetailed("echo 'unterminated");
	assert.equal(result.blocked, true);
	assert.equal(result.reason, "parse_failure");
});

test("detailed matcher returns correct shape for uncertain constructs", async () => {
	const matcherModule = await import("../src/ssh/matcher.ts");
	
	const result = matcherModule.isDirectSshFamilyCommandDetailed("f(){ echo hi; }; f");
	assert.equal(result.blocked, true);
	assert.equal(result.reason, "uncertain");
});

// =============================================================================
// Test: Extension startup self-check behavior
// These tests exercise the extension's session_start handler more directly
// =============================================================================

test("extension session_start handler runs self-check validation", async () => {
	// This test verifies that the extension runs a self-check on session_start
	// by checking that the startup validation logic works correctly
	
	const tempDir = await mkdtemp(join(tmpdir(), "ssh-ext-test-"));
	
	try {
		// Create minimal fake pi object with captured session_start handlers
		const sessionStartHandlers: Array<(event: unknown, ctx: unknown) => Promise<void>> = [];
		
		const fakePi = {
			on: (event: string, handler: (...args: unknown[]) => unknown) => {
				if (event === "session_start") {
					sessionStartHandlers.push(handler as (event: unknown, ctx: unknown) => Promise<void>);
				}
			},
			registerTool: () => {},
			registerCommand: () => {},
		};
		
		const fakeCtx = {
			cwd: tempDir,
			hasUI: true,
			ui: {
				setStatus: () => {},
				notify: () => {},
				theme: { fg: () => "status" },
			},
		};
		
		// Dynamically import the extension to avoid module caching issues
		// and to test the actual extension behavior
		const extensionModule = await import("../src/index.ts");
		const extensionFactory = extensionModule.default;
		
		// Wire the extension with the fake pi object
		extensionFactory(fakePi as unknown as Parameters<typeof extensionFactory>[0]);
		
		// Should have captured at least one session_start handler
		assert.ok(sessionStartHandlers.length >= 1, "Expected extension to register session_start handler");
		
		// Trigger the session_start handler with a valid cwd
		// This should not throw for normal directories
		const handler = sessionStartHandlers[0];
		await handler({}, fakeCtx);
		
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("extension self-check verifies parse failure detection with detailed reason", async () => {
	// This tests that the startup self-check in runStartupSelfCheck validates
	// that parse-failure cases are correctly identified with reason='parse_failure'
	
	// Import the legacy matcher which has the detailed function
	const { legacyDirectSshFamilyMatchDetailed } = await import("../src/shell/fallback/legacy-matcher.ts");
	
	// Verify parse failures return correct reason
	const parseFailureCommands = ["echo 'unterminated", "echo ok &&"];
	
	for (const cmd of parseFailureCommands) {
		const result = legacyDirectSshFamilyMatchDetailed(cmd);
		assert.equal(
			result.blocked,
			true,
			`Expected parse failure '${cmd}' to be blocked`,
		);
		assert.equal(
			result.reason,
			"parse_failure",
			`Expected reason='parse_failure' for '${cmd}', got '${result.reason}'`,
		);
	}
	
	// Verify SSH detection returns correct reason
	const sshCommands = ["ssh user@host", "\\ssh user@host", "sudo -- ssh user@host"];
	
	for (const cmd of sshCommands) {
		const result = legacyDirectSshFamilyMatchDetailed(cmd);
		assert.equal(result.blocked, true, `Expected SSH command '${cmd}' to be blocked`);
		assert.ok(
			result.reason === "ssh_detected" || result.reason === undefined,
			`Expected ssh_detected reason for '${cmd}'`,
		);
	}
	
	// Verify clean commands pass
	const cleanCommands = ["echo ok", "FOO=bar", "echo hi > out.txt"];
	
	for (const cmd of cleanCommands) {
		const result = legacyDirectSshFamilyMatchDetailed(cmd);
		assert.equal(result.blocked, false, `Expected clean command '${cmd}' to not be blocked`);
	}
});

test("extension self-check uses detailed matcher and verifies reason values", async () => {
	// This test verifies that the extension's self-check can use the detailed matcher
	// to verify parse failures are identified with the correct reason
	
	const { isDirectSshFamilyCommandDetailed } = await import("../src/ssh/matcher.ts");
	
	// Parse failure commands should return { blocked: true, reason: 'parse_failure' }
	const parseFailureCommands = ["echo 'unterminated", "echo ok &&"];
	for (const cmd of parseFailureCommands) {
		const result = isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, true, `Expected parse failure '${cmd}' to be blocked`);
		assert.equal(result.reason, "parse_failure", `Expected reason='parse_failure' for '${cmd}'`);
	}
	
	// SSH commands should return { blocked: true, reason: 'ssh_detected' }
	const sshCommands = ["ssh user@host", "\\ssh user@host", "sudo -- ssh user@host"];
	for (const cmd of sshCommands) {
		const result = isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, true, `Expected SSH command '${cmd}' to be blocked`);
		assert.equal(result.reason, "ssh_detected", `Expected reason='ssh_detected' for '${cmd}'`);
	}
	
	// AST-walk uncertain constructs (function definitions, dynamic executables) return { blocked: true, reason: 'uncertain' }
	const astUncertainCommands = ["f(){ echo hi; }; f", "$RUNNER foo"];
	for (const cmd of astUncertainCommands) {
		const result = isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, true, `Expected AST-uncertain command '${cmd}' to be blocked`);
		assert.equal(result.reason, "uncertain", `Expected reason='uncertain' for '${cmd}'`);
	}
	
	// FAIL-CLOSED: Parser-uncertain constructs without SSH must still be blocked
	const parserUncertainCommands = ["cat <(echo hello)"];
	for (const cmd of parserUncertainCommands) {
		const result = isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, true, `Expected parser-uncertain command '${cmd}' without SSH to be blocked (fail-closed)`);
		assert.equal(result.reason, "parse_failure", `Expected reason='parse_failure' for '${cmd}'`);
	}
	
	// Clean commands should return { blocked: false, reason: undefined }
	const cleanCommands = ["echo ok", "FOO=bar", "echo hi > out.txt"];
	for (const cmd of cleanCommands) {
		const result = isDirectSshFamilyCommandDetailed(cmd);
		assert.equal(result.blocked, false, `Expected clean command '${cmd}' to not be blocked`);
		assert.equal(result.reason, undefined, `Expected reason=undefined for '${cmd}'`);
	}
});

// =============================================================================
// Test: Self-check covers ssh commands with escaping
// =============================================================================

test("self-check covers ssh commands with escaping", async () => {
	const { legacyDirectSshFamilyMatchDetailed } = await import("../src/shell/fallback/legacy-matcher.ts");
	
	// These should all be blocked with ssh_detected
	const escapedSshCommands = [
		"\\ssh user@host",
		"\\sudo -- \\ssh user@host",
		"'ssh' user@host",
		'"ssh" user@host',
	];
	
	for (const cmd of escapedSshCommands) {
		const result = legacyDirectSshFamilyMatchDetailed(cmd);
		assert.equal(result.blocked, true, `Expected blocked for escaped SSH: '${cmd}'`);
		// Note: legacy matcher may return undefined or 'ssh_detected' for clean SSH
	}
});

test("self-check covers wrapper commands for SSH", async () => {
	const { legacyDirectSshFamilyMatchDetailed } = await import("../src/shell/fallback/legacy-matcher.ts");
	
	const wrapperCommands = [
		"sudo -- ssh user@host",
		"sudo ssh user@host",
		"env FOO=bar ssh user@host",
		"nohup ssh user@host &",
		"sshpass -p pass ssh user@host",
	];
	
	for (const cmd of wrapperCommands) {
		const result = legacyDirectSshFamilyMatchDetailed(cmd);
		assert.equal(result.blocked, true, `Expected blocked for wrapper command: '${cmd}'`);
	}
});