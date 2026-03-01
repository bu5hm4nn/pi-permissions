/**
 * TDD RED tests for policy store schema v2 with dual-domain grants.
 *
 * Requirements:
 * - Schema version bump from 1 to 2
 * - Domain-tagged grants (domain: "ssh" | "bash")
 * - Backward compatibility: existing v1 files are migrated to v2 with domain: "ssh" default
 * - New permissions config can be stored alongside grants
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readPolicy, writePolicy, upsertGrant } from "../src/policy/store.ts";
import { emptyPolicyFile, type PolicyFile, type PolicyGrant } from "../src/policy/schema.ts";

async function createTempDir(): Promise<string> {
	return mkdtemp(join(tmpdir(), "policy-schema-v2-"));
}

// --- Schema version tests ---

test("emptyPolicyFile() returns version 2", () => {
	const policy = emptyPolicyFile();
	assert.equal(policy.version, 2, "Expected emptyPolicyFile to return version 2");
});

test("PolicyFile type allows version 2", () => {
	// Type-level test: this should compile without errors
	const policy: PolicyFile = {
		version: 2,
		updatedAt: new Date().toISOString(),
		grants: [],
	};
	assert.equal(policy.version, 2);
});

// --- Domain-tagged grants tests ---

test("PolicyGrant type includes domain field", () => {
	// Type-level test: this should compile without errors
	const grant: PolicyGrant = {
		fingerprint: "abc123",
		target: "user@host",
		commandPreview: "echo hello",
		createdAt: new Date().toISOString(),
		domain: "ssh",
	};
	assert.equal(grant.domain, "ssh");
});

test("PolicyGrant domain accepts 'ssh' | 'bash' values", () => {
	const sshGrant: PolicyGrant = {
		fingerprint: "abc123",
		target: "user@host",
		commandPreview: "echo hello",
		createdAt: new Date().toISOString(),
		domain: "ssh",
	};
	const bashGrant: PolicyGrant = {
		fingerprint: "def456",
		target: "",
		commandPreview: "ls -la",
		createdAt: new Date().toISOString(),
		domain: "bash",
	};
	assert.equal(sshGrant.domain, "ssh");
	assert.equal(bashGrant.domain, "bash");
});

test("upsertGrant preserves domain field", () => {
	const policy = emptyPolicyFile();
	const grant: PolicyGrant = {
		fingerprint: "abc123",
		target: "user@host",
		commandPreview: "echo hello",
		createdAt: new Date().toISOString(),
		domain: "bash",
	};
	const updated = upsertGrant(policy, grant);
	const found = updated.grants.find((g) => g.fingerprint === "abc123");
	assert.equal(found?.domain, "bash", "Expected domain to be preserved in upserted grant");
});

// --- Backward compatibility tests ---

test("readPolicy migrates v1 file to v2 with domain: 'ssh' default", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{
					fingerprint: "legacy-fp",
					target: "user@host",
					commandPreview: "echo legacy",
					createdAt: "2026-01-01T00:00:00.000Z",
				},
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		assert.equal(policy.version, 2, "Expected migrated policy to have version 2");
		assert.equal(policy.grants.length, 1, "Expected one grant after migration");
		assert.equal(policy.grants[0].domain, "ssh", "Expected migrated grant to have domain: 'ssh'");
		assert.equal(policy.grants[0].fingerprint, "legacy-fp");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("readPolicy handles v2 file with domain fields intact", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const v2Content = {
			version: 2,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{
					fingerprint: "ssh-fp",
					target: "user@host",
					commandPreview: "echo ssh",
					createdAt: "2026-01-01T00:00:00.000Z",
					domain: "ssh",
				},
				{
					fingerprint: "bash-fp",
					target: "",
					commandPreview: "ls -la",
					createdAt: "2026-01-01T00:00:00.000Z",
					domain: "bash",
				},
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v2Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		assert.equal(policy.version, 2);
		assert.equal(policy.grants.length, 2);
		const sshGrant = policy.grants.find((g) => g.fingerprint === "ssh-fp");
		const bashGrant = policy.grants.find((g) => g.fingerprint === "bash-fp");
		assert.equal(sshGrant?.domain, "ssh");
		assert.equal(bashGrant?.domain, "bash");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("writePolicy persists domain field in grants", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const policy: PolicyFile = {
			version: 2,
			updatedAt: new Date().toISOString(),
			grants: [
				{
					fingerprint: "bash-grant",
					target: "",
					commandPreview: "cat /etc/passwd",
					createdAt: new Date().toISOString(),
					domain: "bash",
				},
			],
		};

		await writePolicy(policyPath, policy);

		const raw = await readFile(policyPath, "utf-8");
		const parsed = JSON.parse(raw);
		assert.equal(parsed.version, 2);
		assert.equal(parsed.grants[0].domain, "bash");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- Permissions config tests ---

test("PolicyFile type includes optional permissions config", () => {
	// Type-level test: this should compile without errors
	const policy: PolicyFile = {
		version: 2,
		updatedAt: new Date().toISOString(),
		grants: [],
		permissions: {
			ssh: { enabled: true },
			bash: { enabled: false },
		},
	};
	assert.equal(policy.permissions?.ssh?.enabled, true);
	assert.equal(policy.permissions?.bash?.enabled, false);
});

test("readPolicy preserves permissions config from file", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const v2Content = {
			version: 2,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [],
			permissions: {
				ssh: { enabled: true },
				bash: { enabled: false },
			},
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v2Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		assert.equal(policy.permissions?.ssh?.enabled, true);
		assert.equal(policy.permissions?.bash?.enabled, false);
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("writePolicy persists permissions config", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const policy: PolicyFile = {
			version: 2,
			updatedAt: new Date().toISOString(),
			grants: [],
			permissions: {
				ssh: { enabled: false },
				bash: { enabled: true },
			},
		};

		await writePolicy(policyPath, policy);

		const raw = await readFile(policyPath, "utf-8");
		const parsed = JSON.parse(raw);
		assert.deepEqual(parsed.permissions, {
			ssh: { enabled: false },
			bash: { enabled: true },
		});
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("readPolicy migrates v1 file without permissions to v2 with undefined permissions", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		assert.equal(policy.version, 2);
		assert.equal(policy.permissions, undefined, "Expected migrated v1 policy to have no permissions config");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- Schema version invariants ---

test("readPolicy rejects version 0 or future versions > 2", async () => {
	const tempDir = await createTempDir();
	try {
		const v0Path = join(tempDir, "v0.json");
		const v3Path = join(tempDir, "v3.json");

		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(v0Path, JSON.stringify({ version: 0, grants: [] }), { mode: 0o600 });
		await writeFile(v3Path, JSON.stringify({ version: 3, grants: [] }), { mode: 0o600 });

		await assert.rejects(readPolicy(v0Path), /Invalid policy schema/);
		await assert.rejects(readPolicy(v3Path), /Invalid policy schema/);
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- Domain filtering helpers (to be implemented) ---

test("filterGrantsByDomain returns only grants for specified domain", async () => {
	const { filterGrantsByDomain } = await import("../src/policy/store.ts");
	const grants: PolicyGrant[] = [
		{ fingerprint: "fp1", target: "user@host", commandPreview: "cmd1", createdAt: "", domain: "ssh" },
		{ fingerprint: "fp2", target: "", commandPreview: "cmd2", createdAt: "", domain: "bash" },
		{ fingerprint: "fp3", target: "other@host", commandPreview: "cmd3", createdAt: "", domain: "ssh" },
	];

	const sshGrants = filterGrantsByDomain(grants, "ssh");
	const bashGrants = filterGrantsByDomain(grants, "bash");

	assert.equal(sshGrants.length, 2);
	assert.equal(bashGrants.length, 1);
	assert.equal(sshGrants.every((g: PolicyGrant) => g.domain === "ssh"), true);
	assert.equal(bashGrants.every((g: PolicyGrant) => g.domain === "bash"), true);
});

test("upsertGrant with missing domain defaults to 'ssh' for backward compatibility", () => {
	const policy = emptyPolicyFile();
	// Create a grant without domain (simulating old code path)
	const grantWithoutDomain = {
		fingerprint: "no-domain",
		target: "user@host",
		commandPreview: "echo test",
		createdAt: new Date().toISOString(),
	} as PolicyGrant;

	const updated = upsertGrant(policy, grantWithoutDomain);
	const found = updated.grants.find((g) => g.fingerprint === "no-domain");

	assert.equal(found?.domain, "ssh", "Expected missing domain to default to 'ssh'");
});
