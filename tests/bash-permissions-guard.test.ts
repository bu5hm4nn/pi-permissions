import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// =============================================================================
// Test Fixtures & Helpers
// =============================================================================

async function setupTempEnv(): Promise<{ home: string; project: string; cleanup: () => Promise<void> }> {
	const root = await mkdtemp(join(tmpdir(), "bash-guard-"));
	const home = join(root, "home");
	const project = join(root, "project");
	await mkdir(home, { recursive: true });
	await mkdir(project, { recursive: true });
	return {
		home,
		project,
		async cleanup() {
			await rm(root, { recursive: true, force: true });
		},
	};
}

// =============================================================================
// readPermissionsConfig tests
// =============================================================================

test("readPermissionsConfig returns default disabled when no config files exist", async () => {
	const { readPermissionsConfig } = await import("../src/policy/store.ts");
	const env = await setupTempEnv();
	const oldHome = process.env.HOME;
	process.env.HOME = env.home;
	try {
		const config = await readPermissionsConfig(env.project);
		assert.equal(config.ssh.enabled, true, "SSH should be enabled by default");
		assert.equal(config.bash.enabled, false, "Bash should be disabled by default");
	} finally {
		process.env.HOME = oldHome;
		await env.cleanup();
	}
});

test("readPermissionsConfig reads global permissions.json", async () => {
	const { readPermissionsConfig } = await import("../src/policy/store.ts");
	const env = await setupTempEnv();
	const oldHome = process.env.HOME;
	process.env.HOME = env.home;
	try {
		const configDir = join(env.home, ".pi", "agent");
		await mkdir(configDir, { recursive: true, mode: 0o700 });
		await writeFile(
			join(configDir, "permissions.json"),
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: true }, bash: { enabled: true } },
			}),
			{ mode: 0o600 },
		);
		const config = await readPermissionsConfig(env.project);
		assert.equal(config.ssh.enabled, true);
		assert.equal(config.bash.enabled, true);
	} finally {
		process.env.HOME = oldHome;
		await env.cleanup();
	}
});

test("readPermissionsConfig reads project permissions.json and merges with global", async () => {
	const { readPermissionsConfig } = await import("../src/policy/store.ts");
	const env = await setupTempEnv();
	const oldHome = process.env.HOME;
	process.env.HOME = env.home;
	try {
		// Global: ssh=true, bash=false
		const globalDir = join(env.home, ".pi", "agent");
		await mkdir(globalDir, { recursive: true, mode: 0o700 });
		await writeFile(
			join(globalDir, "permissions.json"),
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: true }, bash: { enabled: false } },
			}),
			{ mode: 0o600 },
		);

		// Project: ssh=false, bash=true (overrides global)
		const projectDir = join(env.project, ".pi");
		await mkdir(projectDir, { recursive: true, mode: 0o700 });
		await writeFile(
			join(projectDir, "permissions.json"),
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: false }, bash: { enabled: true } },
			}),
			{ mode: 0o600 },
		);

		const config = await readPermissionsConfig(env.project);
		// Project overrides global
		assert.equal(config.ssh.enabled, false);
		assert.equal(config.bash.enabled, true);
	} finally {
		process.env.HOME = oldHome;
		await env.cleanup();
	}
});

test("readPermissionsConfig ignores insecure global permissions.json (group/world writable)", async () => {
	const { readPermissionsConfig } = await import("../src/policy/store.ts");
	const env = await setupTempEnv();
	const oldHome = process.env.HOME;
	process.env.HOME = env.home;
	try {
		const globalDir = join(env.home, ".pi", "agent");
		await mkdir(globalDir, { recursive: true, mode: 0o700 });
		const globalConfigPath = join(globalDir, "permissions.json");
		await writeFile(
			globalConfigPath,
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: false }, bash: { enabled: true } },
			}),
			{ mode: 0o600 },
		);
		await chmod(globalConfigPath, 0o622);

		const config = await readPermissionsConfig(env.project);
		assert.equal(config.ssh.enabled, true, "Insecure global config should be ignored");
		assert.equal(config.bash.enabled, false, "Insecure global config should be ignored");
	} finally {
		process.env.HOME = oldHome;
		await env.cleanup();
	}
});

test("readPermissionsConfig ignores symlinked project permissions.json", async () => {
	const { readPermissionsConfig } = await import("../src/policy/store.ts");
	const env = await setupTempEnv();
	const oldHome = process.env.HOME;
	process.env.HOME = env.home;
	try {
		const projectDir = join(env.project, ".pi");
		await mkdir(projectDir, { recursive: true, mode: 0o700 });
		const targetPath = join(env.project, "permissions-target.json");
		await writeFile(
			targetPath,
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: false }, bash: { enabled: true } },
			}),
			{ mode: 0o600 },
		);
		await symlink(targetPath, join(projectDir, "permissions.json"));

		const config = await readPermissionsConfig(env.project);
		assert.equal(config.ssh.enabled, true, "Symlinked project config should be ignored");
		assert.equal(config.bash.enabled, false, "Symlinked project config should be ignored");
	} finally {
		process.env.HOME = oldHome;
		await env.cleanup();
	}
});

// =============================================================================
// Guard behavior when bash permissions are DISABLED (default) - passthrough
// =============================================================================

test("tool_call guard passes through bash commands when bash permissions disabled", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: false },
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo hello" } },
		runtime,
	);

	// Should NOT block - passthrough when bash permissions disabled
	assert.equal(result, undefined, "Expected passthrough (no blocking) when bash permissions disabled");
});

test("tool_call guard still blocks direct SSH when bash permissions disabled", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => true,
		bashPermissions: { enabled: false },
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ssh user@host" } },
		runtime,
	);

	assert.deepEqual(result, { block: true, reason: "Direct SSH-family commands are blocked. Use ssh_bash." });
});

// =============================================================================
// Guard behavior when bash permissions are ENABLED - requires approval
// =============================================================================

test("tool_call guard requires approval for bash commands when bash permissions enabled", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	// Track if approval callback was invoked
	let approvalRequested = false;
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		checkBashApproval: async () => {
			approvalRequested = true;
			return { approved: false, scope: "none" as const };
		},
		hasUI: false,
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "rm -rf /tmp/test" } },
		runtime,
	);

	assert.equal(approvalRequested, true, "Expected bash approval check to be invoked");
	// When not approved and no UI, should block
	assert.deepEqual(result, { block: true, reason: "Bash command not approved. Enable UI for approval prompts." });
});

test("tool_call guard passes through approved bash commands", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		checkBashApproval: async () => ({ approved: true, scope: "session" as const }),
		hasUI: true,
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ls -la" } },
		runtime,
	);

	assert.equal(result, undefined, "Expected passthrough for approved bash command");
});

test("tool_call guard uses domain-tagged fingerprints for bash commands", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	let capturedFingerprint: string | null = null;
	let capturedDomain: string | null = null;
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		checkBashApproval: async (fp: string, domain: string) => {
			capturedFingerprint = fp;
			capturedDomain = domain;
			return { approved: true, scope: "session" as const };
		},
		hasUI: true,
	};

	await handleToolCallGuard(
		{ toolName: "bash", input: { command: "npm install" } },
		runtime,
	);

	assert.notEqual(capturedFingerprint, null, "Expected fingerprint to be captured");
	assert.equal(capturedDomain, "bash", "Expected domain to be 'bash'");
});

// =============================================================================
// Guard behavior preserves existing SSH blocking
// =============================================================================

test("existing SSH blocking behavior unchanged when bash permissions enabled", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: (cmd: string) => cmd.includes("ssh"),
		bashPermissions: { enabled: true },
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ssh user@host" } },
		runtime,
	);

	// SSH blocking takes precedence over bash approval flow
	assert.deepEqual(result, { block: true, reason: "Direct SSH-family commands are blocked. Use ssh_bash." });
});

test("guard health failure blocks all bash commands regardless of permissions", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: false,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo safe" } },
		runtime,
	);

	assert.deepEqual(result, { block: true, reason: "SSH guard unhealthy: emergency fail-closed mode" });
});

// =============================================================================
// user_bash guard behavior with bash permissions
// =============================================================================

test("user_bash guard passes through when bash permissions disabled", async () => {
	const { handleUserBashGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: false },
	};

	const result = await handleUserBashGuard({ command: "echo hello" }, runtime);

	assert.equal(result, undefined, "Expected passthrough for user_bash when bash permissions disabled");
});

test("user_bash still blocks direct SSH when bash permissions disabled", async () => {
	const { handleUserBashGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => true,
		bashPermissions: { enabled: false },
	};

	const result = await handleUserBashGuard({ command: "ssh user@host" }, runtime);

	assert.equal(result?.result?.exitCode, 126);
	assert.match(result?.result?.output || "", /direct SSH-family commands are disabled/i);
});

// =============================================================================
// Command pattern analysis integration
// =============================================================================

test("bash approval uses command pattern analysis for reusable fingerprints", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	let capturedPatterns: string[] = [];
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		checkBashApproval: async (_fp: string, _domain: string, patterns?: string[]) => {
			capturedPatterns = patterns || [];
			return { approved: true, scope: "session" as const };
		},
		hasUI: true,
	};

	await handleToolCallGuard(
		{ toolName: "bash", input: { command: "git status && npm test" } },
		runtime,
	);

	// Should extract command patterns like "git status *" and "npm test *"
	assert.equal(capturedPatterns.length > 0, true, "Expected command patterns to be extracted");
});

// =============================================================================
// No-UI mode behavior
// =============================================================================

test("bash guard blocks unapproved commands in no-UI mode", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		checkBashApproval: async () => ({ approved: false, scope: "none" as const }),
		hasUI: false,
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "rm -rf /" } },
		runtime,
	);

	assert.deepEqual(result, { block: true, reason: "Bash command not approved. Enable UI for approval prompts." });
});


test("bash guard blocks approved commands in no-UI mode", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		checkBashApproval: async () => ({ approved: true, scope: "session" as const }),
		hasUI: false,
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo should-block" } },
		runtime,
	);

	assert.deepEqual(result, { block: true, reason: "Bash command not approved. Enable UI for approval prompts." });
});

// =============================================================================
// Fingerprint computation for bash domain
// =============================================================================

test("bash fingerprints differ from SSH fingerprints for same command", async () => {
	// This tests that the domain tagging produces different fingerprints
	const { computeBashFingerprint, computeFingerprint } = await import("../src/policy/fingerprint.ts");

	const command = "echo hello";
	const sshFingerprint = computeFingerprint({ target: "user@host", command });
	const bashFingerprint = computeBashFingerprint(command);

	assert.notEqual(sshFingerprint, bashFingerprint, "Bash and SSH fingerprints should differ");
});

// =============================================================================
// Existing SSH behavior unchanged (regression tests)
// =============================================================================

test("tool_call guard existing behavior: blocks direct ssh when healthy", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => true,
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "ssh user@host" } },
		runtime,
	);

	assert.deepEqual(result, { block: true, reason: "Direct SSH-family commands are blocked. Use ssh_bash." });
});

test("tool_call guard existing behavior: passes non-ssh commands without bashPermissions", async () => {
	const { handleToolCallGuard } = await import("../src/ssh/guard.ts");
	const runtime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		// No bashPermissions set - should use default (disabled)
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "echo hello" } },
		runtime,
	);

	assert.equal(result, undefined, "Expected passthrough for non-SSH commands when bashPermissions not set");
});

// =============================================================================
// Secure write tests (symlink protection)
// =============================================================================

test("writeAtomicSecure throws on symlinked target path (security)", async () => {
	const { writeAtomicSecure } = await import("../src/policy/store.ts");
	const root = await mkdtemp(join(tmpdir(), "secure-write-test-"));
	try {
		// Create a target file to symlink to
		const targetPath = join(root, "target-file.json");
		await writeFile(targetPath, '{"should": "not be overwritten"}', { mode: 0o600 });

		// Create directory with symlinked permissions.json
		const configDir = join(root, "config");
		await mkdir(configDir, { recursive: true });
		const symlinkPath = join(configDir, "permissions.json");
		await symlink(targetPath, symlinkPath);

		// Attempting to write to symlinked path should fail
		await assert.rejects(
			async () => {
				await writeAtomicSecure(symlinkPath, '{"permissions": {}}');
			},
			/symlink|ENOENT|EXIST/i,
			"Should reject writing to symlinked path"
		);

		// Target file should not be modified
		const targetContent = await import("node:fs/promises").then(fs => fs.readFile(targetPath, "utf-8"));
		assert.equal(targetContent, '{"should": "not be overwritten"}', "Target file should not be overwritten");
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});

test("writeAtomicSecure writes successfully to non-symlink path", async () => {
	const { writeAtomicSecure } = await import("../src/policy/store.ts");
	const root = await mkdtemp(join(tmpdir(), "secure-write-ok-"));
	try {
		const configDir = join(root, ".pi");
		await mkdir(configDir, { recursive: true });
		const configPath = join(configDir, "permissions.json");

		await writeAtomicSecure(configPath, '{"permissions": {"bash": {"enabled": true}}}');

		const content = await import("node:fs/promises").then(fs => fs.readFile(configPath, "utf-8"));
		assert.equal(content, '{"permissions": {"bash": {"enabled": true}}}');
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
