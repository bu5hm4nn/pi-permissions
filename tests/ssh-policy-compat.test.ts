/**
 * TDD tests for /ssh-policy backward compatibility with deprecation warning.
 *
 * Requirements:
 * 1. /ssh-policy continues to work exactly as before (list/clear/revoke/reload)
 * 2. When using /ssh-policy, show a one-time deprecation notice suggesting /permissions
 * 3. Keep backward compatibility - no breaking changes
 */
import test from "node:test";
import assert from "node:assert/strict";
import { registerPolicyCommands, resetSshPolicyDeprecationFlag } from "../src/commands/ssh-policy.ts";

type RegisteredCommand = {
	description?: string;
	handler: (args: string, ctx: any) => Promise<void> | void;
};

function createMockPi() {
	const commands = new Map<string, RegisteredCommand>();
	return {
		commands,
		registerCommand(name: string, def: RegisteredCommand) {
			commands.set(name, def);
		},
	};
}

function createMockState() {
	const sessionFingerprints = new Set<string>(["abc123def456"]);
	return {
		getSessionFingerprints: () => sessionFingerprints,
		clearSession: () => sessionFingerprints.clear(),
		revokeSessionByPrefix: (prefix: string) => {
			for (const fp of sessionFingerprints) {
				if (fp.startsWith(prefix)) {
					sessionFingerprints.delete(fp);
					return { ok: true, message: `Revoked session fingerprint ${fp}` };
				}
			}
			return { ok: false, message: "No matching fingerprint" };
		},
		readGlobal: async () => ({
			version: 1,
			updatedAt: new Date().toISOString(),
			grants: [
				{
					fingerprint: "deadbeef12345678",
					target: "user@host",
					commandPreview: "ls -la",
					createdAt: new Date().toISOString(),
				},
			],
		}),
		readProject: async () => ({ version: 1, updatedAt: new Date().toISOString(), grants: [] }),
		isProjectTrusted: async () => false,
		writeGlobal: async () => {},
		writeProject: async () => {},
		revokeGlobalByPrefix: async () => ({ ok: false, message: "No matching fingerprint" }),
		revokeProjectByPrefix: async () => ({ ok: false, message: "No matching fingerprint" }),
		reload: async () => {},
	};
}

function registerCommands(state?: ReturnType<typeof createMockState>) {
	const pi = createMockPi();
	registerPolicyCommands(pi as any, (state ?? createMockState()) as any);
	return pi.commands;
}

// =============================================================================
// Backward compatibility - /ssh-policy continues to work
// =============================================================================

test("/ssh-policy command remains registered alongside /permissions", () => {
	const commands = registerCommands();
	assert.equal(commands.has("ssh-policy"), true, "Expected /ssh-policy to be registered");
	assert.equal(commands.has("permissions"), true, "Expected /permissions to be registered");
});

test("/ssh-policy list produces output without errors", async () => {
	const commands = registerCommands();
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	await command.handler("list", ctx);
	const infoMessages = notifications.filter((n) => n.level === "info");
	assert.ok(infoMessages.length >= 1, "Expected /ssh-policy list to produce info output");
});

test("/ssh-policy reload works without errors", async () => {
	const commands = registerCommands();
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	await command.handler("reload", ctx);
	const successMessage = notifications.find((n) => n.level === "info" && /reload/i.test(n.message));
	assert.ok(successMessage, "Expected /ssh-policy reload to report success");
});

test("/ssh-policy clear session works without errors", async () => {
	const state = createMockState();
	const commands = registerCommands(state);
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	await command.handler("clear session", ctx);
	const successMessage = notifications.find((n) => n.level === "info" && /clear/i.test(n.message));
	assert.ok(successMessage, "Expected /ssh-policy clear session to report success");
	assert.equal(state.getSessionFingerprints().size, 0, "Expected session to be cleared");
});

test("/ssh-policy revoke session works without errors", async () => {
	const state = createMockState();
	const commands = registerCommands(state);
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	await command.handler("revoke session abc123def456", ctx);
	const successMessage = notifications.find((n) => n.level === "info" && /revoke/i.test(n.message));
	assert.ok(successMessage, "Expected /ssh-policy revoke session to report success");
});

// =============================================================================
// Deprecation notice - one-time warning
// =============================================================================

test("/ssh-policy shows one-time deprecation notice on first use", async () => {
	resetSshPolicyDeprecationFlag();
	const commands = registerCommands();
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	await command.handler("list", ctx);

	const deprecationNotice = notifications.find(
		(n) => n.level === "warning" && /deprecat/i.test(n.message) && /\/permissions/i.test(n.message)
	);
	assert.ok(deprecationNotice, "Expected deprecation notice mentioning /permissions on first /ssh-policy use");
});

test("/ssh-policy deprecation notice is shown only once per session", async () => {
	resetSshPolicyDeprecationFlag();
	const commands = registerCommands();
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	// First call
	await command.handler("list", ctx);
	const firstCallDeprecations = notifications.filter(
		(n) => n.level === "warning" && /deprecat/i.test(n.message)
	);
	assert.equal(firstCallDeprecations.length, 1, "Expected exactly one deprecation notice on first call");

	// Second call
	notifications.length = 0;
	await command.handler("list", ctx);
	const secondCallDeprecations = notifications.filter(
		(n) => n.level === "warning" && /deprecat/i.test(n.message)
	);
	assert.equal(secondCallDeprecations.length, 0, "Expected no deprecation notice on subsequent calls");
});

test("/ssh-policy deprecation notice appears before command output", async () => {
	resetSshPolicyDeprecationFlag();
	const commands = registerCommands();
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	await command.handler("list", ctx);

	const deprecationIndex = notifications.findIndex(
		(n) => n.level === "warning" && /deprecat/i.test(n.message)
	);
	const listOutputIndex = notifications.findIndex(
		(n) => n.level === "info" && /scope/i.test(n.message)
	);

	assert.ok(deprecationIndex >= 0, "Expected deprecation notice");
	assert.ok(listOutputIndex >= 0, "Expected list output");
	assert.ok(deprecationIndex < listOutputIndex, "Expected deprecation notice to appear before list output");
});

test("/ssh-policy deprecation notice mentions /permissions as alternative", async () => {
	resetSshPolicyDeprecationFlag();
	const commands = registerCommands();
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	await command.handler("list", ctx);

	const deprecationNotice = notifications.find(
		(n) => n.level === "warning" && /deprecat/i.test(n.message)
	);
	assert.ok(deprecationNotice, "Expected deprecation notice");
	assert.ok(
		/\/permissions/i.test(deprecationNotice.message),
		"Expected deprecation notice to mention /permissions command"
	);
});

// =============================================================================
// Deprecation state is reset properly
// =============================================================================

test("deprecation notice flag can be reset for testing purposes", async () => {
	resetSshPolicyDeprecationFlag();
	const commands = registerCommands();
	const command = commands.get("ssh-policy");
	assert.ok(command?.handler);

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => notifications.push({ message, level }),
			confirm: async () => true,
		},
	};

	// First call shows deprecation
	await command.handler("list", ctx);
	const firstCount = notifications.filter((n) => n.level === "warning" && /deprecat/i.test(n.message)).length;
	assert.equal(firstCount, 1, "Expected deprecation on first call");

	// Second call should not show deprecation
	notifications.length = 0;
	await command.handler("reload", ctx);
	const secondCount = notifications.filter((n) => n.level === "warning" && /deprecat/i.test(n.message)).length;
	assert.equal(secondCount, 0, "Expected no deprecation on subsequent call");
});
