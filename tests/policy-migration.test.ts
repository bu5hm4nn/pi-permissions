/**
 * TDD tests for v1→v2 policy migration compatibility.
 *
 * Edge cases covered:
 * 1. Reading v1 file with grants missing domain field → migrated to domain: "ssh"
 * 2. Reading v2 file with mixed domain grants → preserved as-is
 * 3. Writing always produces v2 format with domain field
 * 4. /ssh-policy list shows grants correctly regardless of source version
 * 5. Round-trip migration: read v1 → write → read back → all v2 format
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readPolicy, writePolicy, upsertGrant, filterGrantsByDomain } from "../src/policy/store.ts";
import type { PolicyFile, PolicyGrant } from "../src/policy/schema.ts";

async function createTempDir(): Promise<string> {
	return mkdtemp(join(tmpdir(), "policy-migration-"));
}

// --- Edge case: v1 grants with various missing fields ---

test("migration: v1 grant missing only domain field gets domain: 'ssh'", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{
					fingerprint: "fp-no-domain",
					target: "user@host",
					commandPreview: "echo test",
					createdAt: "2026-01-01T00:00:00.000Z",
					// domain field intentionally missing
				},
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		assert.equal(policy.version, 2, "Expected version to be migrated to 2");
		assert.equal(policy.grants.length, 1);
		assert.equal(policy.grants[0].domain, "ssh", "Expected missing domain to default to 'ssh'");
		assert.equal(policy.grants[0].fingerprint, "fp-no-domain");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("migration: v1 file with multiple grants all get domain: 'ssh'", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{ fingerprint: "fp1", target: "user@host1", commandPreview: "cmd1", createdAt: "2026-01-01T00:00:00.000Z" },
				{ fingerprint: "fp2", target: "user@host2", commandPreview: "cmd2", createdAt: "2026-01-02T00:00:00.000Z" },
				{ fingerprint: "fp3", target: "root@server", commandPreview: "cmd3", createdAt: "2026-01-03T00:00:00.000Z" },
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		assert.equal(policy.version, 2);
		assert.equal(policy.grants.length, 3);
		for (const grant of policy.grants) {
			assert.equal(grant.domain, "ssh", `Expected grant ${grant.fingerprint} to have domain: 'ssh'`);
		}
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("migration: v1 file with empty grants array migrates to v2 empty", async () => {
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

		assert.equal(policy.version, 2, "Expected version to be migrated to 2");
		assert.equal(policy.grants.length, 0);
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- Edge case: v2 file with mixed domain grants ---

test("migration: v2 file with mixed ssh/bash domains preserved as-is", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const v2Content = {
			version: 2,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{ fingerprint: "ssh-fp1", target: "user@host", commandPreview: "echo ssh", createdAt: "2026-01-01T00:00:00.000Z", domain: "ssh" },
				{ fingerprint: "bash-fp1", target: "", commandPreview: "ls -la", createdAt: "2026-01-02T00:00:00.000Z", domain: "bash" },
				{ fingerprint: "ssh-fp2", target: "root@server", commandPreview: "whoami", createdAt: "2026-01-03T00:00:00.000Z", domain: "ssh" },
				{ fingerprint: "bash-fp2", target: "", commandPreview: "cat /etc/passwd", createdAt: "2026-01-04T00:00:00.000Z", domain: "bash" },
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v2Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		assert.equal(policy.version, 2);
		assert.equal(policy.grants.length, 4);

		const sshGrants = filterGrantsByDomain(policy.grants, "ssh");
		const bashGrants = filterGrantsByDomain(policy.grants, "bash");

		assert.equal(sshGrants.length, 2, "Expected 2 ssh grants");
		assert.equal(bashGrants.length, 2, "Expected 2 bash grants");
		assert.ok(sshGrants.some((g) => g.fingerprint === "ssh-fp1"));
		assert.ok(sshGrants.some((g) => g.fingerprint === "ssh-fp2"));
		assert.ok(bashGrants.some((g) => g.fingerprint === "bash-fp1"));
		assert.ok(bashGrants.some((g) => g.fingerprint === "bash-fp2"));
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- Edge case: Write always produces v2 format ---

test("migration: writePolicy always writes version 2 with domain field", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const policy: PolicyFile = {
			version: 2,
			updatedAt: new Date().toISOString(),
			grants: [
				{ fingerprint: "test-fp", target: "user@host", commandPreview: "echo test", createdAt: new Date().toISOString(), domain: "ssh" },
			],
		};

		await writePolicy(policyPath, policy);

		const raw = await readFile(policyPath, "utf-8");
		const parsed = JSON.parse(raw);

		assert.equal(parsed.version, 2, "Expected written version to be 2");
		assert.equal(parsed.grants.length, 1);
		assert.equal(parsed.grants[0].domain, "ssh", "Expected domain field to be present in written grant");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("migration: writePolicy includes domain field for bash grants", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const policy: PolicyFile = {
			version: 2,
			updatedAt: new Date().toISOString(),
			grants: [
				{ fingerprint: "bash-fp", target: "", commandPreview: "rm -rf /tmp/*", createdAt: new Date().toISOString(), domain: "bash" },
			],
		};

		await writePolicy(policyPath, policy);

		const raw = await readFile(policyPath, "utf-8");
		const parsed = JSON.parse(raw);

		assert.equal(parsed.grants[0].domain, "bash", "Expected bash domain to be preserved");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- Round-trip migration test ---

test("migration: round-trip read v1 → write → read back produces v2", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");

		// Write v1 format file
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{ fingerprint: "legacy-fp", target: "user@host", commandPreview: "echo legacy", createdAt: "2026-01-01T00:00:00.000Z" },
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		// Read (migrates to v2 in memory)
		const policy = await readPolicy(policyPath);
		assert.equal(policy.version, 2);
		assert.equal(policy.grants[0].domain, "ssh");

		// Write back
		await writePolicy(policyPath, policy);

		// Verify raw file is v2 format
		const raw = await readFile(policyPath, "utf-8");
		const parsed = JSON.parse(raw);
		assert.equal(parsed.version, 2, "Expected persisted version to be 2");
		assert.equal(parsed.grants[0].domain, "ssh", "Expected persisted grant to have domain field");

		// Read again to confirm consistency
		const reread = await readPolicy(policyPath);
		assert.equal(reread.version, 2);
		assert.equal(reread.grants[0].domain, "ssh");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- upsertGrant migration behavior ---

test("migration: upsertGrant on migrated v1 policy preserves domain: 'ssh'", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");

		// Write v1 format file
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{ fingerprint: "existing-fp", target: "user@host", commandPreview: "echo existing", createdAt: "2026-01-01T00:00:00.000Z" },
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		// Read and migrate
		let policy = await readPolicy(policyPath);

		// Upsert a new grant
		const newGrant: PolicyGrant = {
			fingerprint: "new-fp",
			target: "admin@server",
			commandPreview: "echo new",
			createdAt: new Date().toISOString(),
			domain: "ssh",
		};
		policy = upsertGrant(policy, newGrant);

		assert.equal(policy.version, 2);
		assert.equal(policy.grants.length, 2);

		const existing = policy.grants.find((g) => g.fingerprint === "existing-fp");
		const added = policy.grants.find((g) => g.fingerprint === "new-fp");

		assert.equal(existing?.domain, "ssh", "Expected migrated grant to keep domain: 'ssh'");
		assert.equal(added?.domain, "ssh", "Expected new grant to have domain: 'ssh'");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("migration: upsertGrant can add bash grant to migrated v1 policy", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");

		// Write v1 format file (ssh only, no domain)
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{ fingerprint: "ssh-fp", target: "user@host", commandPreview: "echo ssh", createdAt: "2026-01-01T00:00:00.000Z" },
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		// Read and migrate
		let policy = await readPolicy(policyPath);

		// Upsert a bash grant
		const bashGrant: PolicyGrant = {
			fingerprint: "bash-fp",
			target: "",
			commandPreview: "ls -la",
			createdAt: new Date().toISOString(),
			domain: "bash",
		};
		policy = upsertGrant(policy, bashGrant);

		assert.equal(policy.version, 2);
		assert.equal(policy.grants.length, 2);

		const sshGrants = filterGrantsByDomain(policy.grants, "ssh");
		const bashGrants = filterGrantsByDomain(policy.grants, "bash");

		assert.equal(sshGrants.length, 1, "Expected 1 ssh grant (migrated)");
		assert.equal(bashGrants.length, 1, "Expected 1 bash grant (added)");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- Edge case: grant with undefined domain in v2 file (malformed) ---

test("migration: v2 file with grant missing domain field defaults to 'ssh'", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		// Malformed v2 file - has version 2 but grants without domain
		const malformedV2Content = {
			version: 2,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{ fingerprint: "no-domain-fp", target: "user@host", commandPreview: "echo test", createdAt: "2026-01-01T00:00:00.000Z" },
				// domain intentionally missing despite v2
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(malformedV2Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		assert.equal(policy.version, 2);
		assert.equal(policy.grants.length, 1);
		assert.equal(policy.grants[0].domain, "ssh", "Expected missing domain in v2 file to default to 'ssh'");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- Edge case: preserving other grant fields during migration ---

test("migration: all grant fields preserved during v1→v2 migration", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-15T12:30:45.000Z",
			grants: [
				{
					fingerprint: "detailed-fp",
					target: "admin@production-server.example.com",
					commandPreview: "sudo systemctl restart nginx",
					createdAt: "2026-01-10T09:15:30.000Z",
				},
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);
		const grant = policy.grants[0];

		assert.equal(grant.fingerprint, "detailed-fp");
		assert.equal(grant.target, "admin@production-server.example.com");
		assert.equal(grant.commandPreview, "sudo systemctl restart nginx");
		assert.equal(grant.createdAt, "2026-01-10T09:15:30.000Z");
		assert.equal(grant.domain, "ssh", "Expected domain to be added");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// --- /ssh-policy list command compatibility (unit-testable parts) ---

test("migration: filterGrantsByDomain correctly filters migrated grants", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");

		// Write v1 format (all grants will be migrated to ssh domain)
		const v1Content = {
			version: 1,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{ fingerprint: "fp1", target: "user@host1", commandPreview: "cmd1", createdAt: "2026-01-01T00:00:00.000Z" },
				{ fingerprint: "fp2", target: "user@host2", commandPreview: "cmd2", createdAt: "2026-01-02T00:00:00.000Z" },
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v1Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		// All should be ssh domain after migration
		const sshGrants = filterGrantsByDomain(policy.grants, "ssh");
		const bashGrants = filterGrantsByDomain(policy.grants, "bash");

		assert.equal(sshGrants.length, 2, "Expected all migrated grants to be in ssh domain");
		assert.equal(bashGrants.length, 0, "Expected no bash grants from v1 file");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("migration: filterGrantsByDomain works on mixed v2 grants", async () => {
	const tempDir = await createTempDir();
	try {
		const policyPath = join(tempDir, "policy.json");

		const v2Content = {
			version: 2,
			updatedAt: "2026-01-01T00:00:00.000Z",
			grants: [
				{ fingerprint: "ssh1", target: "user@host", commandPreview: "ssh cmd", createdAt: "2026-01-01T00:00:00.000Z", domain: "ssh" },
				{ fingerprint: "bash1", target: "", commandPreview: "bash cmd", createdAt: "2026-01-02T00:00:00.000Z", domain: "bash" },
				{ fingerprint: "ssh2", target: "root@server", commandPreview: "ssh cmd2", createdAt: "2026-01-03T00:00:00.000Z", domain: "ssh" },
			],
		};
		await mkdir(tempDir, { recursive: true, mode: 0o700 });
		await writeFile(policyPath, JSON.stringify(v2Content), { mode: 0o600 });

		const policy = await readPolicy(policyPath);

		const sshGrants = filterGrantsByDomain(policy.grants, "ssh");
		const bashGrants = filterGrantsByDomain(policy.grants, "bash");

		assert.equal(sshGrants.length, 2);
		assert.equal(bashGrants.length, 1);
		assert.ok(sshGrants.every((g) => g.domain === "ssh"));
		assert.ok(bashGrants.every((g) => g.domain === "bash"));
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});
