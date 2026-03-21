import test from "node:test";
import assert from "node:assert/strict";
import { handleToolCallGuard, handleUserBashGuard } from "../src/ssh/guard.ts";
import { isDirectSshFamilyCommand } from "../src/ssh/matcher.ts";

// =============================================================================
// Test: Guard distinguishes blocking reasons when detailed matcher available
// These tests verify the guard can use detailed matcher results for better error messages
// =============================================================================

test("tool_call guard distinguishes parse_failure from ssh_detected in block reason", async () => {
	// Create a mock matcher that provides detailed results
	const detailedMatcherResults = new Map<string, { blocked: boolean; reason?: string }>([
		["echo 'unterminated", { blocked: true, reason: "parse_failure" }],
		["f(){ echo hi; }; f", { blocked: true, reason: "uncertain" }],
		["ssh user@host", { blocked: true, reason: "ssh_detected" }],
		["echo ok", { blocked: false, reason: undefined }],
	]);
	
	// Mock matcher that returns detailed results (object with blocked + reason)
	const detailedMatcher = (cmd: string): { blocked: boolean; reason?: string } => {
		const result = detailedMatcherResults.get(cmd);
		if (!result) {
			const blocked = isDirectSshFamilyCommand(cmd);
			return { blocked, reason: blocked ? "ssh_detected" : undefined };
		}
		return result;
	};
	
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo 'unterminated" } },
		{ guardHealthy: true, matchDirectSsh: detailedMatcher },
	);
	
	assert.equal(result?.block, true, "Expected parse failure to be blocked");
	assert.match(
		result?.reason ?? "",
		/parse|syntax|invalid/i,
		"Expected reason to mention parse/syntax/invalid for parse failure",
	);
});

test("tool_call guard distinguishes uncertain from ssh_detected in block reason", async () => {
	const detailedMatcherResults = new Map<string, { blocked: boolean; reason?: string }>([
		["f(){ echo hi; }; f", { blocked: true, reason: "uncertain" }],
	]);
	
	const detailedMatcher = (cmd: string): { blocked: boolean; reason?: string } => {
		const result = detailedMatcherResults.get(cmd);
		if (!result) {
			const blocked = isDirectSshFamilyCommand(cmd);
			return { blocked, reason: blocked ? "ssh_detected" : undefined };
		}
		return result;
	};
	
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "f(){ echo hi; }; f" } },
		{ guardHealthy: true, matchDirectSsh: detailedMatcher },
	);
	
	assert.equal(result?.block, true, "Expected uncertain construct to be blocked");
	assert.match(
		result?.reason ?? "",
		/uncertain|complex|unsupported|unable to parse/i,
		"Expected reason to mention uncertain/complex for uncertain construct",
	);
});

test("tool_call guard returns SSH-specific reason for ssh_detected", async () => {
	const detailedMatcherResults = new Map<string, { blocked: boolean; reason?: string }>([
		["ssh user@host", { blocked: true, reason: "ssh_detected" }],
	]);
	
	const detailedMatcher = (cmd: string): { blocked: boolean; reason?: string } => {
		const result = detailedMatcherResults.get(cmd);
		if (!result) {
			const blocked = isDirectSshFamilyCommand(cmd);
			return { blocked, reason: blocked ? "ssh_detected" : undefined };
		}
		return result;
	};
	
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ssh user@host" } },
		{ guardHealthy: true, matchDirectSsh: detailedMatcher },
	);
	
	assert.equal(result?.block, true, "Expected SSH command to be blocked");
	assert.match(
		result?.reason ?? "",
		/ssh|SSH/i,
		"Expected reason to mention SSH for SSH-detected block",
	);
});

test("user_bash guard distinguishes parse_failure from ssh_detected in output", async () => {
	const detailedMatcherResults = new Map<string, { blocked: boolean; reason?: string }>([
		["echo 'unterminated", { blocked: true, reason: "parse_failure" }],
	]);
	
	const detailedMatcher = (cmd: string): { blocked: boolean; reason?: string } => {
		const result = detailedMatcherResults.get(cmd);
		if (!result) {
			const blocked = isDirectSshFamilyCommand(cmd);
			return { blocked, reason: blocked ? "ssh_detected" : undefined };
		}
		return result;
	};
	
	const result = await handleUserBashGuard(
		{ command: "echo 'unterminated" },
		{ guardHealthy: true, matchDirectSsh: detailedMatcher },
	);
	
	assert.ok(result, "Expected handleUserBashGuard to return a result");
	assert.equal(result?.result?.exitCode, 126, "Expected exit code 126 for blocked command");
	assert.match(
		result?.result?.output ?? "",
		/parse|syntax|invalid/i,
		"Expected output to mention parse/syntax/invalid for parse failure",
	);
});

test("user_bash guard distinguishes uncertain from ssh_detected in output", async () => {
	const detailedMatcherResults = new Map<string, { blocked: boolean; reason?: string }>([
		["f(){ echo hi; }; f", { blocked: true, reason: "uncertain" }],
	]);
	
	const detailedMatcher = (cmd: string): { blocked: boolean; reason?: string } => {
		const result = detailedMatcherResults.get(cmd);
		if (!result) {
			const blocked = isDirectSshFamilyCommand(cmd);
			return { blocked, reason: blocked ? "ssh_detected" : undefined };
		}
		return result;
	};
	
	const result = await handleUserBashGuard(
		{ command: "f(){ echo hi; }; f" },
		{ guardHealthy: true, matchDirectSsh: detailedMatcher },
	);
	
	assert.ok(result, "Expected handleUserBashGuard to return a result");
	assert.equal(result?.result?.exitCode, 126, "Expected exit code 126 for blocked command");
	assert.match(
		result?.result?.output ?? "",
		/uncertain|complex|unsupported|unable to parse/i,
		"Expected output to mention uncertain/complex for uncertain construct",
	);
});

// =============================================================================
// Existing tests for boolean matcher behavior
// =============================================================================

test("tool_call guard blocks parser-uncertain heredocs without SSH (fail-closed)", async () => {
	const uncertainHeredoc = String.raw`python3 - <<'PY'
from pathlib import Path
print('hello')
PY`;
	// Use the detailed matcher to get proper reason codes
	const { isDirectSshFamilyCommandDetailed } = await import("../src/ssh/matcher.ts");
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: uncertainHeredoc } },
		{ guardHealthy: true, matchDirectSsh: isDirectSshFamilyCommandDetailed },
	);
	// FAIL-CLOSED: Parser-uncertain heredocs without SSH are blocked (can't confirm no SSH)
	assert.equal(result?.block, true, "Expected heredoc without SSH to be blocked (fail-closed)");
	assert.match(result?.reason ?? "", /Cannot safely parse|parse_failure/i, "Expected parse_failure message");
});

test("user_bash guard blocks parser-uncertain heredocs without SSH (fail-closed)", async () => {
	const uncertainHeredoc = String.raw`python3 - <<'PY'
from pathlib import Path
print('hello')
PY`;
	const result = await handleUserBashGuard(
		{ command: uncertainHeredoc },
		{ guardHealthy: true, matchDirectSsh: isDirectSshFamilyCommand },
	);
	// FAIL-CLOSED: Parser-uncertain heredocs without SSH are blocked (can't confirm no SSH)
	assert.equal(result?.result?.exitCode, 126, "Expected exit code 126 for blocked command");
	assert.match(result?.result?.output ?? "", /Blocked|blocked|SSH/i);
});

test("default matcher still blocks direct ssh-family commands", () => {
	assert.equal(isDirectSshFamilyCommand("ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("sudo -- ssh user@host"), true);
});

test("unhealthy guard blocks all commands", async () => {
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo ok" } },
		{ guardHealthy: false, matchDirectSsh: () => false },
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /fail-closed|unhealthy/i);
});

test("user_bash guard blocks all commands when unhealthy", async () => {
	const result = await handleUserBashGuard(
		{ command: "echo ok" },
		{ guardHealthy: false, matchDirectSsh: () => false },
	);
	assert.ok(result, "Expected result when guard unhealthy");
	assert.equal(result?.result?.exitCode, 126);
	assert.match(result?.result?.output ?? "", /fail-closed|unhealthy/i);
});