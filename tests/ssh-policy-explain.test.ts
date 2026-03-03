import test from "node:test";
import assert from "node:assert/strict";
import { computeFingerprint } from "../src/policy/fingerprint.ts";
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

function registerCommands(state: any) {
	const pi = createMockPi();
	registerPolicyCommands(pi as any, state as any);
	return pi.commands;
}

test("/ssh-policy explain validates usage", async () => {
	resetSshPolicyDeprecationFlag();
	const state = {
		getSessionFingerprints: () => new Set<string>(),
		clearSession: () => {},
		revokeSessionByPrefix: () => ({ ok: false, message: "No match" }),
		readGlobal: async () => ({ version: 2, updatedAt: new Date().toISOString(), grants: [] }),
		readProject: async () => ({ version: 2, updatedAt: new Date().toISOString(), grants: [] }),
		isProjectTrusted: async () => false,
		writeGlobal: async () => {},
		writeProject: async () => {},
		revokeGlobalByPrefix: async () => ({ ok: false, message: "No match" }),
		revokeProjectByPrefix: async () => ({ ok: false, message: "No match" }),
		reload: async () => {},
	};
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

	await command!.handler("explain", ctx);
	const usage = notifications.find((n) => n.level === "error" && /Usage: \/ssh-policy explain/.test(n.message));
	assert.ok(usage, "Expected explain usage error");
});

test("/ssh-policy explain reports fallback-based reusable approval", async () => {
	resetSshPolicyDeprecationFlag();
	const target = "dev@example.com";
	const broadPattern = "curl POST *";
	const broadFingerprint = computeFingerprint({ target, command: broadPattern });

	const state = {
		getSessionFingerprints: () => new Set<string>(),
		clearSession: () => {},
		revokeSessionByPrefix: () => ({ ok: false, message: "No match" }),
		readGlobal: async () => ({
			version: 2,
			updatedAt: new Date().toISOString(),
			grants: [{ fingerprint: broadFingerprint, target, commandPreview: broadPattern, createdAt: new Date().toISOString(), domain: "ssh" }],
		}),
		readProject: async () => ({ version: 2, updatedAt: new Date().toISOString(), grants: [] }),
		isProjectTrusted: async () => false,
		writeGlobal: async () => {},
		writeProject: async () => {},
		revokeGlobalByPrefix: async () => ({ ok: false, message: "No match" }),
		revokeProjectByPrefix: async () => ({ ok: false, message: "No match" }),
		reload: async () => {},
	};
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

	await command!.handler("explain dev@example.com curl -d 'a=1' https://api.example.com/a", ctx);
	const explain = notifications.find((n) => n.level === "info" && n.message.includes("Scope: explain"));
	assert.ok(explain, "Expected explain output");
	assert.match(explain!.message, /Would auto-approve: true/);
	assert.match(explain!.message, /Decision reason: all_reusable_patterns_approved/);
	assert.match(explain!.message, /\(fallback\)/);
});

test("/ssh-policy explain reports missing required patterns", async () => {
	resetSshPolicyDeprecationFlag();
	const state = {
		getSessionFingerprints: () => new Set<string>(),
		clearSession: () => {},
		revokeSessionByPrefix: () => ({ ok: false, message: "No match" }),
		readGlobal: async () => ({ version: 2, updatedAt: new Date().toISOString(), grants: [] }),
		readProject: async () => ({ version: 2, updatedAt: new Date().toISOString(), grants: [] }),
		isProjectTrusted: async () => false,
		writeGlobal: async () => {},
		writeProject: async () => {},
		revokeGlobalByPrefix: async () => ({ ok: false, message: "No match" }),
		revokeProjectByPrefix: async () => ({ ok: false, message: "No match" }),
		reload: async () => {},
	};
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

	await command!.handler("explain dev@example.com echo hello", ctx);
	const explain = notifications.find((n) => n.level === "info" && n.message.includes("Scope: explain"));
	assert.ok(explain, "Expected explain output");
	assert.match(explain!.message, /Would auto-approve: false/);
	assert.match(explain!.message, /Decision reason: missing_required_patterns/);
});
