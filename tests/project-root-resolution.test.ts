/**
 * TDD tests for project root resolution in permissions persistence.
 *
 * Issue: Project-level permissions.json is read/written relative to ctx.cwd
 * instead of the resolved project root (git root), so running from a subdirectory
 * breaks permission persistence.
 *
 * Fix: Use resolveProjectRoot() in readPermissionsConfig and /permissions command persistence.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readPermissionsConfig, resolveProjectRoot } from "../src/policy/store.ts";
import { registerPolicyCommands } from "../src/commands/ssh-policy.ts";

// --- Test helpers ---

async function createTempProjectWithSubdir(): Promise<{
	root: string;
	home: string;
	projectRoot: string;
	subdir: string;
	cleanup: () => Promise<void>;
}> {
	const root = await mkdtemp(join(tmpdir(), "project-root-test-"));
	const home = join(root, "home");
	const projectRoot = join(root, "project");
	const subdir = join(projectRoot, "src", "deep", "nested");

	await mkdir(home, { recursive: true });
	await mkdir(projectRoot, { recursive: true });
	await mkdir(subdir, { recursive: true });

	// Create .git directory to mark project root
	await mkdir(join(projectRoot, ".git"), { recursive: true });

	return {
		root,
		home,
		projectRoot,
		subdir,
		cleanup: async () => {
			await rm(root, { recursive: true, force: true });
		},
	};
}

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

// --- resolveProjectRoot tests ---

test("resolveProjectRoot finds .git ancestor from subdirectory", async () => {
	const { projectRoot, subdir, cleanup } = await createTempProjectWithSubdir();
	try {
		const resolved = resolveProjectRoot(subdir);
		assert.equal(resolved, projectRoot, "Should resolve to project root containing .git");
	} finally {
		await cleanup();
	}
});

test("resolveProjectRoot returns startCwd when no .git ancestor exists", async () => {
	const tempDir = await mkdtemp(join(tmpdir(), "no-git-"));
	await mkdir(tempDir, { recursive: true });
	try {
		const resolved = resolveProjectRoot(tempDir);
		assert.equal(resolved, tempDir, "Should return startCwd when no .git found");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("resolveProjectRoot returns same directory when .git is in startCwd", async () => {
	const { projectRoot, cleanup } = await createTempProjectWithSubdir();
	try {
		const resolved = resolveProjectRoot(projectRoot);
		assert.equal(resolved, projectRoot, "Should return same directory when it contains .git");
	} finally {
		await cleanup();
	}
});

// --- readPermissionsConfig project root resolution tests ---

test("readPermissionsConfig reads from project root when called from subdirectory", async () => {
	const { home, projectRoot, subdir, cleanup } = await createTempProjectWithSubdir();
	const oldHome = process.env.HOME;
	process.env.HOME = home;

	try {
		// Write permissions.json at project root
		const piDir = join(projectRoot, ".pi");
		await mkdir(piDir, { recursive: true, mode: 0o700 });
		await writeFile(
			join(piDir, "permissions.json"),
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: false }, bash: { enabled: true } },
			}),
			{ mode: 0o600 },
		);

		// Read config from subdirectory - should find project root's config
		const config = await readPermissionsConfig(subdir);

		assert.equal(config.ssh.enabled, false, "Should read ssh disabled from project root config");
		assert.equal(config.bash.enabled, true, "Should read bash enabled from project root config");
	} finally {
		process.env.HOME = oldHome;
		await cleanup();
	}
});

test("readPermissionsConfig does NOT find config written in subdirectory (project root wins)", async () => {
	const { home, projectRoot, subdir, cleanup } = await createTempProjectWithSubdir();
	const oldHome = process.env.HOME;
	process.env.HOME = home;

	try {
		// Write permissions.json in subdirectory (wrong location)
		const subdirPi = join(subdir, ".pi");
		await mkdir(subdirPi, { recursive: true, mode: 0o700 });
		await writeFile(
			join(subdirPi, "permissions.json"),
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: false }, bash: { enabled: false } },
			}),
			{ mode: 0o600 },
		);

		// Read config from subdirectory - should NOT find subdir's config
		const config = await readPermissionsConfig(subdir);

		// Expected: default values (no config found at project root)
		assert.equal(config.ssh.enabled, true, "Should get default ssh=true (subdir config ignored)");
		assert.equal(config.bash.enabled, false, "Should get default bash=false (subdir config ignored)");
	} finally {
		process.env.HOME = oldHome;
		await cleanup();
	}
});

test("readPermissionsConfig from project root works correctly", async () => {
	const { home, projectRoot, cleanup } = await createTempProjectWithSubdir();
	const oldHome = process.env.HOME;
	process.env.HOME = home;

	try {
		// Write permissions.json at project root
		const piDir = join(projectRoot, ".pi");
		await mkdir(piDir, { recursive: true, mode: 0o700 });
		await writeFile(
			join(piDir, "permissions.json"),
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: false }, bash: { enabled: true } },
			}),
			{ mode: 0o600 },
		);

		// Read config from project root directly
		const config = await readPermissionsConfig(projectRoot);

		assert.equal(config.ssh.enabled, false, "Should read ssh disabled");
		assert.equal(config.bash.enabled, true, "Should read bash enabled");
	} finally {
		process.env.HOME = oldHome;
		await cleanup();
	}
});

// --- /permissions command project root resolution tests ---

test("/permissions Save to project writes to project root when cwd is subdirectory", async () => {
	const { home, projectRoot, subdir, cleanup } = await createTempProjectWithSubdir();
	const oldHome = process.env.HOME;
	process.env.HOME = home;

	try {
		const pi = createMockPi();
		registerPolicyCommands(pi as any, createMockState() as any);
		const command = pi.commands.get("permissions");

		// Run /permissions with cwd as subdirectory
		const ctx = {
			hasUI: true,
			cwd: subdir, // Running from subdirectory!
			ui: {
				notify() {},
				select: async () => "Save to project (.pi/permissions.json)",
			},
		};

		await command!.handler("", ctx);

		// Verify file was written to project root, NOT subdirectory
		const projectConfigPath = join(projectRoot, ".pi", "permissions.json");
		const subdirConfigPath = join(subdir, ".pi", "permissions.json");

		let projectExists = false;
		let subdirExists = false;

		try {
			await stat(projectConfigPath);
			projectExists = true;
		} catch {}
		try {
			await stat(subdirConfigPath);
			subdirExists = true;
		} catch {}

		assert.equal(projectExists, true, "Config should be written to project root .pi/permissions.json");
		assert.equal(subdirExists, false, "Config should NOT be written to subdirectory .pi/permissions.json");

		// Verify content
		const parsed = JSON.parse(await readFile(projectConfigPath, "utf-8"));
		assert.equal(parsed?.permissions?.ssh?.enabled, true, "Default ssh enabled");
		assert.equal(parsed?.permissions?.bash?.enabled, false, "Default bash disabled");
	} finally {
		process.env.HOME = oldHome;
		await cleanup();
	}
});

test("/permissions reads existing project config from root when cwd is subdirectory", async () => {
	const { home, projectRoot, subdir, cleanup } = await createTempProjectWithSubdir();
	const oldHome = process.env.HOME;
	process.env.HOME = home;

	try {
		// Pre-create project config at root
		const piDir = join(projectRoot, ".pi");
		await mkdir(piDir, { recursive: true, mode: 0o700 });
		await writeFile(
			join(piDir, "permissions.json"),
			JSON.stringify({
				version: 1,
				permissions: { ssh: { enabled: false }, bash: { enabled: true } },
			}),
			{ mode: 0o600 },
		);

		const pi = createMockPi();
		registerPolicyCommands(pi as any, createMockState() as any);
		const command = pi.commands.get("permissions");

		const capturedOptions: string[][] = [];

		// Run /permissions with cwd as subdirectory
		const ctx = {
			hasUI: true,
			cwd: subdir, // Running from subdirectory!
			ui: {
				notify() {},
				select: async (_title: string, options: string[]) => {
					capturedOptions.push([...options]);
					return "Cancel"; // Don't save, just capture initial state
				},
			},
		};

		await command!.handler("", ctx);

		// First menu should show ssh disabled (read from project root)
		const firstSSH = capturedOptions[0].find((o) => o.includes("SSH"));
		assert.ok(
			firstSSH?.includes("○") || firstSSH?.includes("disabled"),
			`SSH should show as disabled from project root config, got: ${firstSSH}`,
		);

		const firstBash = capturedOptions[0].find((o) => o.includes("Bash"));
		assert.ok(
			firstBash?.includes("✓") || firstBash?.includes("enabled"),
			`Bash should show as enabled from project root config, got: ${firstBash}`,
		);
	} finally {
		process.env.HOME = oldHome;
		await cleanup();
	}
});

// --- Global config should NOT be affected by cwd (sanity check) ---

test("/permissions Save to global works from subdirectory (unaffected by project root)", async () => {
	const { home, projectRoot, subdir, cleanup } = await createTempProjectWithSubdir();
	const oldHome = process.env.HOME;
	process.env.HOME = home;

	try {
		const pi = createMockPi();
		registerPolicyCommands(pi as any, createMockState() as any);
		const command = pi.commands.get("permissions");

		const ctx = {
			hasUI: true,
			cwd: subdir,
			ui: {
				notify() {},
				select: async () => "Save to global (~/.pi/agent/permissions.json)",
			},
		};

		await command!.handler("", ctx);

		const globalPath = join(home, ".pi", "agent", "permissions.json");
		const parsed = JSON.parse(await readFile(globalPath, "utf-8"));
		assert.equal(parsed?.permissions?.ssh?.enabled, true);
		assert.equal(parsed?.permissions?.bash?.enabled, false);
	} finally {
		process.env.HOME = oldHome;
		await cleanup();
	}
});