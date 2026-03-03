import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
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
	return { root, home, project };
}

function registerCommands() {
	const pi = createMockPi();
	registerPolicyCommands(pi as any, createMockState() as any);
	return pi.commands;
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

test("/permissions opens a select menu in UI mode", async () => {
	const commands = registerCommands();
	const command = commands.get("permissions");
	assert.equal(typeof command?.handler, "function", "Expected /permissions command handler");

	let selectCalled = false;
	let selectTitle = "";
	let selectOptions: string[] = [];

	const ctx = {
		hasUI: true,
		cwd: "/tmp",
		ui: {
			notify() {},
			select: async (title: string, options: string[]) => {
				selectCalled = true;
				selectTitle = title;
				selectOptions = options;
				return "Cancel"; // Cancel to exit loop
			},
		},
	};

	await command!.handler("", ctx);
	assert.equal(selectCalled, true, "Expected /permissions to call ui.select");
	assert.equal(selectTitle, "Permissions Configuration", "Expected select title");
});

test("/permissions select menu shows SSH and Bash toggle options", async () => {
	const commands = registerCommands();
	const command = commands.get("permissions");

	let capturedOptions: string[] = [];

	const ctx = {
		hasUI: true,
		cwd: "/tmp",
		ui: {
			notify() {},
			select: async (_title: string, options: string[]) => {
				capturedOptions = options;
				return "Cancel";
			},
		},
	};

	await command!.handler("", ctx);

	const hasSSH = capturedOptions.some((opt) => opt.toLowerCase().includes("ssh"));
	const hasBash = capturedOptions.some((opt) => opt.toLowerCase().includes("bash"));
	const hasSave = capturedOptions.some((opt) => opt.toLowerCase().includes("save"));
	const hasCancel = capturedOptions.some((opt) => opt.toLowerCase().includes("cancel"));

	assert.equal(hasSSH, true, "Expected SSH permissions option");
	assert.equal(hasBash, true, "Expected Bash permissions option");
	assert.equal(hasSave, true, "Expected Save option");
	assert.equal(hasCancel, true, "Expected Cancel option");
});

test("/permissions Save to global persists settings", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	process.env.HOME = temp.home;

	try {
		const commands = registerCommands();
		const command = commands.get("permissions");

		// Create permissions.json to set initial state
		const piDir = join(temp.home, ".pi", "agent");
		await mkdir(piDir, { recursive: true });
		await writeFile(
			join(piDir, "permissions.json"),
			JSON.stringify({ version: 1, permissions: { ssh: { enabled: false }, bash: { enabled: true } } }),
			{ mode: 0o600 },
		);

		let selectCount = 0;
		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				select: async (_title: string, _options: string[]) => {
					selectCount++;
					if (selectCount === 1) {
						return "Save to global (~/.pi/agent/permissions.json)";
					}
					return "Cancel";
				},
			},
		};

		await command!.handler("", ctx);

		const configPath = join(temp.home, ".pi", "agent", "permissions.json");
		const parsed = JSON.parse(await readFile(configPath, "utf-8"));
		assert.equal(parsed?.permissions?.ssh?.enabled, false);
		assert.equal(parsed?.permissions?.bash?.enabled, true);
	} finally {
		process.env.HOME = oldHome;
		await rm(temp.root, { recursive: true, force: true });
	}
});

test("/permissions Save to project persists settings", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	process.env.HOME = temp.home;

	try {
		const commands = registerCommands();
		const command = commands.get("permissions");

		let selectCount = 0;
		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				select: async (_title: string, _options: string[]) => {
					selectCount++;
					if (selectCount === 1) {
						return "Save to project (.pi/permissions.json)";
					}
					return "Cancel";
				},
			},
		};

		await command!.handler("", ctx);

		const configPath = join(temp.project, ".pi", "permissions.json");
		const parsed = JSON.parse(await readFile(configPath, "utf-8"));
		// Default values (ssh enabled, bash disabled)
		assert.equal(parsed?.permissions?.ssh?.enabled, true);
		assert.equal(parsed?.permissions?.bash?.enabled, false);
	} finally {
		process.env.HOME = oldHome;
		await rm(temp.root, { recursive: true, force: true });
	}
});

test("/permissions Cancel does not persist settings", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	process.env.HOME = temp.home;

	try {
		const commands = registerCommands();
		const command = commands.get("permissions");

		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				select: async () => "Cancel",
			},
		};

		await command!.handler("", ctx);

		// No files should be created
		const globalPath = join(temp.home, ".pi", "agent", "permissions.json");
		const projectPath = join(temp.project, ".pi", "permissions.json");

		let globalExists = false;
		let projectExists = false;
		try {
			await stat(globalPath);
			globalExists = true;
		} catch {}
		try {
			await stat(projectPath);
			projectExists = true;
		} catch {}

		assert.equal(globalExists, false, "Global config should not be created on Cancel");
		assert.equal(projectExists, false, "Project config should not be created on Cancel");
	} finally {
		process.env.HOME = oldHome;
		await rm(temp.root, { recursive: true, force: true });
	}
});

test("/permissions toggling SSH updates menu state", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	process.env.HOME = temp.home;

	try {
		const commands = registerCommands();
		const command = commands.get("permissions");

		const capturedOptions: string[][] = [];

		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				select: async (_title: string, options: string[]) => {
					capturedOptions.push([...options]);
					if (capturedOptions.length === 1) {
						// First call - toggle SSH
						const sshOption = options.find((o) => o.includes("SSH"));
						return sshOption;
					}
					if (capturedOptions.length === 2) {
						// Second call - verify toggle happened, then cancel
						return "Cancel";
					}
					return "Cancel";
				},
			},
		};

		await command!.handler("", ctx);

		// Should have been called twice (initial + after toggle)
		assert.equal(capturedOptions.length >= 2, true, "Select should be called at least twice for toggle");

		// First call should show SSH enabled (default)
		const firstSSH = capturedOptions[0].find((o) => o.includes("SSH"));
		assert.ok(firstSSH?.includes("✓") || firstSSH?.includes("enabled"), "SSH should start enabled");

		// Second call should show SSH disabled (after toggle)
		const secondSSH = capturedOptions[1].find((o) => o.includes("SSH"));
		assert.ok(secondSSH?.includes("○") || secondSSH?.includes("disabled"), "SSH should be disabled after toggle");
	} finally {
		process.env.HOME = oldHome;
		await rm(temp.root, { recursive: true, force: true });
	}
});

test("/permissions persisted files use secure modes (files 0o600, dirs 0o700)", async () => {
	const temp = await setupTempProject();
	const oldHome = process.env.HOME;
	process.env.HOME = temp.home;

	try {
		const commands = registerCommands();
		const command = commands.get("permissions");

		const ctx = {
			hasUI: true,
			cwd: temp.project,
			ui: {
				notify() {},
				select: async () => "Save to global (~/.pi/agent/permissions.json)",
			},
		};

		await command!.handler("", ctx);

		const piDir = join(temp.home, ".pi");
		const agentDir = join(piDir, "agent");
		const configPath = join(agentDir, "permissions.json");

		const piDirStat = await stat(piDir);
		const agentDirStat = await stat(agentDir);
		const fileStat = await stat(configPath);

		const mode = (s: any) => s.mode & 0o777;

		assert.equal(mode(piDirStat), 0o700, "~/.pi should have mode 0o700");
		assert.equal(mode(agentDirStat), 0o700, "~/.pi/agent should have mode 0o700");
		assert.equal(mode(fileStat), 0o600, "permissions.json should have mode 0o600");
	} finally {
		process.env.HOME = oldHome;
		await rm(temp.root, { recursive: true, force: true });
	}
});

test("/permissions requires UI mode", async () => {
	const commands = registerCommands();
	const command = commands.get("permissions");

	let notifyMessage = "";
	const ctx = {
		hasUI: false,
		cwd: "/tmp",
		ui: {
			notify(msg: string) {
				notifyMessage = msg;
			},
			select: async () => {
				throw new Error("Should not call select without UI");
			},
		},
	};

	await command!.handler("", ctx);
	assert.ok(notifyMessage.includes("requires UI mode"), "Should notify about UI requirement");
});

test("/permissions handles select returning undefined (escape)", async () => {
	const commands = registerCommands();
	const command = commands.get("permissions");

	let selectCalled = false;
	const ctx = {
		hasUI: true,
		cwd: "/tmp",
		ui: {
			notify() {},
			select: async () => {
				selectCalled = true;
				return undefined; // User pressed escape
			},
		},
	};

	// Should not throw
	await command!.handler("", ctx);
	assert.equal(selectCalled, true, "Select should have been called");
});
