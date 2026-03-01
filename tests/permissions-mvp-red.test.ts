import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { registerPolicyCommands } from "../src/commands/ssh-policy.ts";

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
	return {
		getSessionFingerprints: () => new Set<string>(),
		clearSession: () => {},
		revokeSessionByPrefix: () => ({ ok: false, message: "No matching fingerprint" }),
		readGlobal: async () => ({ version: 1, updatedAt: new Date().toISOString(), grants: [] }),
		readProject: async () => ({ version: 1, updatedAt: new Date().toISOString(), grants: [] }),
		isProjectTrusted: async () => false,
		writeGlobal: async () => {},
		writeProject: async () => {},
		revokeGlobalByPrefix: async () => ({ ok: false, message: "No matching fingerprint" }),
		revokeProjectByPrefix: async () => ({ ok: false, message: "No matching fingerprint" }),
		reload: async () => {},
	};
}

async function setupTempProject() {
	const root = await mkdtemp(join(tmpdir(), "permissions-red-"));
	const home = join(root, "home");
	const project = join(root, "project");
	await mkdir(home, { recursive: true });
	await mkdir(project, { recursive: true });
	return { home, project };
}

function registerCommands() {
	const pi = createMockPi();
	registerPolicyCommands(pi as any, createMockState() as any);
	return pi.commands;
}

function extractToggleLabels(panel: any): string[] {
	const candidates = [panel?.checkboxes, panel?.toggles, panel?.options, panel?.items].filter(Array.isArray);
	if (candidates.length === 0) return [];
	const toggles = candidates[0].filter((item: any) => {
		if (typeof item !== "object" || item === null) return false;
		const type = String(item.type ?? "").toLowerCase();
		return type === "checkbox" || type === "toggle" || "checked" in item || "value" in item;
	});
	return toggles
		.map((item: any) => String(item.label ?? item.title ?? item.name ?? ""))
		.filter(Boolean)
		.map((label) => label.toLowerCase());
}

function extractActionLabels(panel: any): string[] {
	const actions = Array.isArray(panel?.actions) ? panel.actions : [];
	return actions
		.map((action: any) => {
			if (typeof action === "string") return action;
			if (action && typeof action === "object") return action.label ?? action.title ?? action.name ?? action.action ?? "";
			return "";
		})
		.filter(Boolean)
		.map((x: string) => x.toLowerCase());
}

test("/permissions command is registered", () => {
	const commands = registerCommands();
	assert.equal(commands.has("permissions"), true, "Expected /permissions command to be registered");
});

test("/permissions compatibility keeps /ssh-policy registered alongside /permissions", () => {
	const commands = registerCommands();
	assert.equal(commands.has("permissions"), true, "Expected /permissions compatibility command to be registered");
	assert.equal(commands.has("ssh-policy"), true, "Expected /ssh-policy to remain registered for compatibility");
});

test("/permissions opens a configuration menu/panel in UI mode", async () => {
	const commands = registerCommands();
	const command = commands.get("permissions");
	assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

	const panelCalls: any[] = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify() {},
			openPanel: async (panel: any) => {
				panelCalls.push(panel);
				return { action: "cancel" };
			},
		},
	};

	await command!.handler("", ctx);
	assert.equal(panelCalls.length, 1, "Expected /permissions to open exactly one configuration panel in UI mode");
});

test("/permissions MVP panel exposes two SSH/Bash toggles plus Save/Cancel (shape-agnostic)", async () => {
	const commands = registerCommands();
	const command = commands.get("permissions");
	assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

	let capturedPanel: any = null;
	const ctx = {
		hasUI: true,
		ui: {
			notify() {},
			openPanel: async (panel: any) => {
				capturedPanel = panel;
				return { action: "cancel" };
			},
		},
	};

	await command!.handler("", ctx);

	const toggleLabels = extractToggleLabels(capturedPanel);
	assert.equal(toggleLabels.length, 2, "Expected exactly two MVP toggles");
	assert.equal(toggleLabels.some((label) => label.includes("ssh")), true, "Expected one toggle to target SSH permissions");
	assert.equal(toggleLabels.some((label) => label.includes("bash")), true, "Expected one toggle to target Bash permissions");

	const actions = extractActionLabels(capturedPanel);
	const uniqueActions = new Set(actions);
	assert.equal(uniqueActions.size, 2, "Expected exactly two actions");
	assert.equal(uniqueActions.has("save"), true, "Expected Save affordance");
	assert.equal(uniqueActions.has("cancel"), true, "Expected Cancel affordance");
});

test("/permissions Save persists toggled settings", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	const oldCwd = process.cwd();
	process.env.HOME = temp.home;
	process.chdir(temp.project);
	try {
		const commands = registerCommands();
		const command = commands.get("permissions");
		assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				openPanel: async () => ({ action: "save", values: { sshEnabled: false, bashEnabled: true } }),
			},
		};

		await command!.handler("", ctx);

		const configPath = join(temp.home, ".pi", "agent", "permissions.json");
		const parsed = JSON.parse(await readFile(configPath, "utf-8"));
		assert.equal(parsed?.permissions?.ssh?.enabled, false);
		assert.equal(parsed?.permissions?.bash?.enabled, true);
	} finally {
		process.env.HOME = oldHome;
		process.chdir(oldCwd);
	}
});

test("/permissions Save with global scope persists only global permissions file", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	const oldCwd = process.cwd();
	process.env.HOME = temp.home;
	process.chdir(temp.project);
	try {
		const commands = registerCommands();
		const command = commands.get("permissions");
		assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				openPanel: async () => ({ action: "save", values: { scope: "global", sshEnabled: false, bashEnabled: true } }),
			},
		};

		await command!.handler("", ctx);

		const globalPath = join(temp.home, ".pi", "agent", "permissions.json");
		const projectPath = join(temp.project, ".pi", "permissions.json");
		const parsedGlobal = JSON.parse(await readFile(globalPath, "utf-8"));
		assert.equal(parsedGlobal?.permissions?.ssh?.enabled, false);
		assert.equal(parsedGlobal?.permissions?.bash?.enabled, true);
		await assert.rejects(stat(projectPath), /ENOENT/);
	} finally {
		process.env.HOME = oldHome;
		process.chdir(oldCwd);
	}
});

test("/permissions Save with project scope persists project file and preserves global for merged-effective behavior", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	const oldCwd = process.cwd();
	process.env.HOME = temp.home;
	process.chdir(temp.project);
	try {
		const commands = registerCommands();
		const command = commands.get("permissions");
		assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

		const globalPath = join(temp.home, ".pi", "agent", "permissions.json");
		const projectPath = join(temp.project, ".pi", "permissions.json");

		const globalSaveCtx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				openPanel: async () => ({ action: "save", values: { scope: "global", sshEnabled: true, bashEnabled: false } }),
			},
		};
		await command!.handler("", globalSaveCtx);

		const projectSaveCtx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				openPanel: async () => ({ action: "save", values: { scope: "project", sshEnabled: false, bashEnabled: false } }),
			},
		};
		await command!.handler("", projectSaveCtx);

		const parsedGlobal = JSON.parse(await readFile(globalPath, "utf-8"));
		const parsedProject = JSON.parse(await readFile(projectPath, "utf-8"));
		assert.equal(parsedGlobal?.permissions?.ssh?.enabled, true, "Expected global SSH baseline to remain true");
		assert.equal(parsedGlobal?.permissions?.bash?.enabled, false, "Expected global Bash baseline to remain false");
		assert.equal(parsedProject?.permissions?.ssh?.enabled, false, "Expected project SSH override persisted");
		assert.equal(parsedProject?.permissions?.bash?.enabled, false, "Expected project Bash value persisted for effective merge");
	} finally {
		process.env.HOME = oldHome;
		process.chdir(oldCwd);
	}
});

test("/permissions Cancel does not persist toggled settings", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	const oldCwd = process.cwd();
	process.env.HOME = temp.home;
	process.chdir(temp.project);
	try {
		const commands = registerCommands();
		const command = commands.get("permissions");
		assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				openPanel: async () => ({ action: "cancel", values: { sshEnabled: false, bashEnabled: true } }),
			},
		};

		await command!.handler("", ctx);

		const configPath = join(temp.home, ".pi", "agent", "permissions.json");
		await assert.rejects(stat(configPath), /ENOENT/);
	} finally {
		process.env.HOME = oldHome;
		process.chdir(oldCwd);
	}
});

test("/permissions global save rejects non-absolute HOME to avoid relative persistence path", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	const oldCwd = process.cwd();
	process.env.HOME = "relative-home";
	process.chdir(temp.project);
	try {
		const commands = registerCommands();
		const command = commands.get("permissions");
		assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

		const notifications: Array<{ message: string; level?: string }> = [];
		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify: (message: string, level?: string) => {
					notifications.push({ message, level });
				},
				openPanel: async () => ({ action: "save", values: { scope: "global", sshEnabled: true, bashEnabled: true } }),
			},
		};

		await assert.doesNotReject(command!.handler("", ctx));
		assert.equal(
			notifications.some((n) => /home|absolute/i.test(String(n.message))),
			true,
			"Expected clear HOME absolute-path validation error via ui.notify",
		);
		await assert.rejects(stat(join(temp.project, "relative-home", ".pi", "agent", "permissions.json")), /ENOENT/);
	} finally {
		process.env.HOME = oldHome;
		process.chdir(oldCwd);
	}
});

test("/permissions global save uses HOME fallback path when HOME is missing (never cwd-relative)", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	const oldCwd = process.cwd();
	const fallbackHome = homedir();
	const fallbackPath = join(fallbackHome, ".pi", "agent", "permissions.json");
	let backup: string | null = null;
	let existed = true;
	process.env.HOME = "";
	process.chdir(temp.project);
	try {
		try {
			backup = await readFile(fallbackPath, "utf-8");
		} catch {
			existed = false;
		}

		const commands = registerCommands();
		const command = commands.get("permissions");
		assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				openPanel: async () => ({ action: "save", values: { scope: "global", sshEnabled: true, bashEnabled: false } }),
			},
		};

		await command!.handler("", ctx);

		await assert.rejects(stat(join(temp.project, ".pi", "agent", "permissions.json")), /ENOENT/);
	} finally {
		if (existed && backup !== null) {
			await writeFile(fallbackPath, backup, "utf-8");
		} else {
			await rm(fallbackPath, { force: true });
		}
		process.env.HOME = oldHome;
		process.chdir(oldCwd);
	}
});

test("/permissions defensively handles missing ui.openPanel by notifying and not throwing", async () => {
	const commands = registerCommands();
	const command = commands.get("permissions");
	assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => {
				notifications.push({ message, level });
			},
		},
	};

	await assert.doesNotReject(command!.handler("", ctx));
	assert.equal(notifications.length > 0, true, "Expected missing openPanel to be reported via ui.notify");
	assert.equal(notifications.some((n) => /openpanel|ui|permissions|error/i.test(String(n.message))), true);
});

test("/permissions wraps openPanel/handler errors and reports via ui.notify", async () => {
	const commands = registerCommands();
	const command = commands.get("permissions");
	assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

	const notifications: Array<{ message: string; level?: string }> = [];
	const ctx = {
		hasUI: true,
		ui: {
			notify: (message: string, level?: string) => {
				notifications.push({ message, level });
			},
			openPanel: async () => {
				throw new Error("panel exploded");
			},
		},
	};

	await assert.doesNotReject(command!.handler("", ctx));
	assert.equal(notifications.some((n) => /panel exploded/i.test(String(n.message))), true, "Expected thrown handler error to be surfaced via notify");
});

test("/permissions persisted files/dirs use secure modes (files 0o600, dirs 0o700)", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	const oldCwd = process.cwd();
	process.env.HOME = temp.home;
	process.chdir(temp.project);
	try {
		const commands = registerCommands();
		const command = commands.get("permissions");
		assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

		const globalCtx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				openPanel: async () => ({ action: "save", values: { scope: "global", sshEnabled: true, bashEnabled: true } }),
			},
		};
		await command!.handler("", globalCtx);

		const projectCtx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				openPanel: async () => ({ action: "save", values: { scope: "project", sshEnabled: true, bashEnabled: true } }),
			},
		};
		await command!.handler("", projectCtx);

		const mode = async (path: string) => (await stat(path)).mode & 0o777;
		assert.equal(await mode(join(temp.home, ".pi")), 0o700, "Expected global .pi directory mode 0o700");
		assert.equal(await mode(join(temp.home, ".pi", "agent")), 0o700, "Expected global agent directory mode 0o700");
		assert.equal(await mode(join(temp.home, ".pi", "agent", "permissions.json")), 0o600, "Expected global file mode 0o600");
		assert.equal(await mode(join(temp.project, ".pi")), 0o700, "Expected project .pi directory mode 0o700");
		assert.equal(await mode(join(temp.project, ".pi", "permissions.json")), 0o600, "Expected project file mode 0o600");
	} finally {
		process.env.HOME = oldHome;
		process.chdir(oldCwd);
	}
});
