import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { readPermissionsConfig, readGlobalPermissionsConfig, readProjectPermissionsConfig } from "../src/policy/store.ts";

test("readGlobalPermissionsConfig reads only global config, ignoring project overrides", async () => {
	const home = mkdtempSync(join(tmpdir(), "global-only-test-"));
	const projectRoot = mkdtempSync(join(tmpdir(), "project-root-"));
	const globalDir = join(home, ".pi", "agent");
	mkdirSync(globalDir, { recursive: true });

	// Global has bash enabled
	writeFileSync(join(globalDir, "permissions.json"), JSON.stringify({ permissions: { ssh: { enabled: true }, bash: { enabled: true } } }), { mode: 0o600 });

	// Project has bash disabled (override)
	const projectDir = join(projectRoot, ".pi");
	mkdirSync(projectDir, { recursive: true });
	writeFileSync(join(projectDir, "permissions.json"), JSON.stringify({ permissions: { bash: { enabled: false } } }), { mode: 0o600 });

	const originalHome = process.env.HOME;
	process.env.HOME = home;

	try {
		// readPermissionsConfig returns effective (merged) config - bash should be disabled
		const effective = await readPermissionsConfig(projectRoot);
		assert.equal(effective.bash.enabled, false, "Effective config should have bash disabled from project override");

		// readGlobalPermissionsConfig should return only global - bash should be enabled
		const globalOnly = await readGlobalPermissionsConfig();
		assert.equal(globalOnly.bash.enabled, true, "Global-only config should have bash enabled (ignoring project override)");
	} finally {
		process.env.HOME = originalHome;
		rmSync(home, { recursive: true, force: true });
		rmSync(projectRoot, { recursive: true, force: true });
	}
});

test("readProjectPermissionsConfig reads only project config, returning defaults for missing keys", async () => {
	const home = mkdtempSync(join(tmpdir(), "proj-default-test-"));
	const projectRoot = mkdtempSync(join(tmpdir(), "project-root-"));
	const globalDir = join(home, ".pi", "agent");
	mkdirSync(globalDir, { recursive: true });

	// Global has bash enabled
	writeFileSync(join(globalDir, "permissions.json"), JSON.stringify({ permissions: { bash: { enabled: true } } }), { mode: 0o600 });

	// Project has no config file
	const originalHome = process.env.HOME;
	process.env.HOME = home;

	try {
		// readProjectPermissionsConfig should return defaults when no project config
		const projectOnly = await readProjectPermissionsConfig(projectRoot);
		assert.equal(projectOnly.bash.enabled, false, "Project-only config should return default (bash disabled)");
		assert.equal(projectOnly.ssh.enabled, true, "Project-only config should return default (ssh enabled)");
	} finally {
		process.env.HOME = originalHome;
		rmSync(home, { recursive: true, force: true });
		rmSync(projectRoot, { recursive: true, force: true });
	}
});

test("readProjectPermissionsConfig reads project config when present, ignoring global", async () => {
	const home = mkdtempSync(join(tmpdir(), "proj-read-test-"));
	const projectRoot = mkdtempSync(join(tmpdir(), "project-root-"));
	const globalDir = join(home, ".pi", "agent");
	mkdirSync(globalDir, { recursive: true });

	// Global has bash enabled, ssh enabled
	writeFileSync(join(globalDir, "permissions.json"), JSON.stringify({ permissions: { ssh: { enabled: true }, bash: { enabled: true } } }), { mode: 0o600 });

	// Project has bash disabled, ssh disabled
	const projectDir = join(projectRoot, ".pi");
	mkdirSync(projectDir, { recursive: true });
	writeFileSync(join(projectDir, "permissions.json"), JSON.stringify({ permissions: { ssh: { enabled: false }, bash: { enabled: false } } }), { mode: 0o600 });

	const originalHome = process.env.HOME;
	process.env.HOME = home;

	try {
		const projectOnly = await readProjectPermissionsConfig(projectRoot);
		assert.equal(projectOnly.bash.enabled, false, "Project-only should have bash disabled from project file");
		assert.equal(projectOnly.ssh.enabled, false, "Project-only should have ssh disabled from project file");
	} finally {
		process.env.HOME = originalHome;
		rmSync(home, { recursive: true, force: true });
		rmSync(projectRoot, { recursive: true, force: true });
	}
});

test("readPermissionsConfig returns effective config (merged)", async () => {
	const home = mkdtempSync(join(tmpdir(), "effective-test-"));
	const projectRoot = mkdtempSync(join(tmpdir(), "project-root-"));
	const globalDir = join(home, ".pi", "agent");
	mkdirSync(globalDir, { recursive: true });

	// Global: ssh enabled, bash disabled (default)
	writeFileSync(join(globalDir, "permissions.json"), JSON.stringify({ permissions: { ssh: { enabled: true }, bash: { enabled: false } } }), { mode: 0o600 });

	// Project: bash enabled (override), ssh disabled (override)
	const projectDir = join(projectRoot, ".pi");
	mkdirSync(projectDir, { recursive: true });
	writeFileSync(join(projectDir, "permissions.json"), JSON.stringify({ permissions: { bash: { enabled: true }, ssh: { enabled: false } } }), { mode: 0o600 });

	const originalHome = process.env.HOME;
	process.env.HOME = home;

	try {
		const effective = await readPermissionsConfig(projectRoot);
		// Effective should reflect project overrides
		assert.equal(effective.bash.enabled, true, "Effective should have bash enabled from project override");
		assert.equal(effective.ssh.enabled, false, "Effective should have ssh disabled from project override");
	} finally {
		process.env.HOME = originalHome;
		rmSync(home, { recursive: true, force: true });
		rmSync(projectRoot, { recursive: true, force: true });
	}
});