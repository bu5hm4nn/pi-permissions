import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS, existsSync, realpathSync } from "node:fs";
import { lstat, mkdir, open, readFile, rename, stat, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { PermissionDomain, PolicyFile, PolicyGrant } from "./schema.ts";
import { emptyPolicyFile } from "./schema.ts";

const MAX_POLICY_BYTES = 1024 * 1024;
const MAX_GRANTS = 10_000;

export interface StorePaths {
	globalPath: string;
	projectPath: string;
	legacyProjectPath: string;
	projectRoot: string;
	projectRootRealpath: string;
	projectId: string;
}

export function resolveProjectRoot(startCwd: string): string {
	let current = startCwd;
	while (true) {
		if (existsSync(join(current, ".git"))) return current;
		const parent = dirname(current);
		if (parent === current) return startCwd;
		current = parent;
	}
}

export function resolveStorePaths(startCwd: string): StorePaths {
	const projectRoot = resolveProjectRoot(startCwd);
	const projectRootRealpath = realpathSync(projectRoot);
	const projectId = createHash("sha256").update(projectRootRealpath).digest("hex");
	const base = join(homedir(), ".pi", "agent");
	return {
		globalPath: join(base, "ssh-policy-global.json"),
		projectPath: join(projectRootRealpath, ".pi", "ssh-bash-permissions.json"),
		legacyProjectPath: join(base, "ssh-policy-projects", `${projectId}.json`),
		projectRoot,
		projectRootRealpath,
		projectId,
	};
}

async function assertSecurePath(path: string): Promise<void> {
	const lst = await lstat(path);
	if (lst.isSymbolicLink()) throw new Error(`Symlink paths are not allowed: ${path}`);
	const s = await stat(path);
	if ((s.mode & 0o022) !== 0) throw new Error(`Insecure file permissions: ${path}`);
	if (typeof process.getuid === "function" && s.uid !== process.getuid()) {
		throw new Error(`Policy file owner mismatch: ${path}`);
	}
	if (s.size > MAX_POLICY_BYTES) throw new Error(`Policy file too large: ${path}`);
}

export async function readPolicy(path: string): Promise<PolicyFile> {
	if (!existsSync(path)) return emptyPolicyFile();
	await assertSecurePath(path);
	const raw = await readFile(path, "utf-8");
	const parsed = JSON.parse(raw) as PolicyFile & { version: number };
	if (!parsed || !Array.isArray(parsed.grants)) {
		throw new Error(`Invalid policy schema: ${path}`);
	}

	// Version validation: accept 1 or 2
	if (parsed.version !== 1 && parsed.version !== 2) {
		throw new Error(`Invalid policy schema: ${path}`);
	}

	const grants = parsed.grants.slice(0, MAX_GRANTS).filter((g) => typeof g?.fingerprint === "string");

	// Migrate v1 grants to v2 by adding domain: "ssh" default
	const migratedGrants: PolicyGrant[] = grants.map((g) => ({
		...g,
		domain: (g.domain as PermissionDomain) ?? "ssh",
	}));

	return {
		version: 2,
		updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : new Date().toISOString(),
		grants: migratedGrants,
		permissions: parsed.permissions,
	};
}

function secureTmpOpenFlags(): number {
	let flags = FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL;
	if (typeof FS_CONSTANTS.O_NOFOLLOW === "number") {
		flags |= FS_CONSTANTS.O_NOFOLLOW;
	}
	return flags;
}

async function writeAtomicSecure(path: string, data: string): Promise<void> {
	const dir = dirname(path);
	const tmp = join(dir, `.tmp-${process.pid}-${Date.now()}-${randomBytes(8).toString("hex")}`);
	const file = await open(tmp, secureTmpOpenFlags(), 0o600);
	try {
		await file.writeFile(data, { encoding: "utf-8" });
		await file.sync();
	} catch (err) {
		await file.close();
		await unlink(tmp).catch(() => {});
		throw err;
	}
	await file.close();
	try {
		await rename(tmp, path);
	} catch (err) {
		await unlink(tmp).catch(() => {});
		throw err;
	}
}

export async function writePolicy(path: string, policy: PolicyFile): Promise<void> {
	const dir = dirname(path);
	await mkdir(dir, { recursive: true, mode: 0o700 });
	if (existsSync(path)) await assertSecurePath(path);
	const data = JSON.stringify(policy, null, 2);
	await writeAtomicSecure(path, data);
}

export function upsertGrant(policy: PolicyFile, grant: PolicyGrant): PolicyFile {
	const byFp = new Map<string, PolicyGrant>();
	for (const g of policy.grants) byFp.set(g.fingerprint, g);
	const existing = byFp.get(grant.fingerprint);
	// Default domain to "ssh" for backward compatibility
	const normalizedGrant: PolicyGrant = {
		...grant,
		domain: grant.domain ?? "ssh",
		createdAt: existing?.createdAt ?? grant.createdAt,
	};
	byFp.set(grant.fingerprint, normalizedGrant);
	return {
		version: 2,
		updatedAt: new Date().toISOString(),
		grants: Array.from(byFp.values()).slice(0, MAX_GRANTS),
		permissions: policy.permissions,
	};
}

export function filterGrantsByDomain(grants: PolicyGrant[], domain: PermissionDomain): PolicyGrant[] {
	return grants.filter((g) => g.domain === domain);
}

export function removeGrantByPrefix(policy: PolicyFile, prefix: string): { policy: PolicyFile; matches: PolicyGrant[] } {
	const matches = policy.grants.filter((g) => g.fingerprint.startsWith(prefix));
	if (matches.length !== 1) return { policy, matches };
	const next = policy.grants.filter((g) => g.fingerprint !== matches[0].fingerprint);
	return {
		matches,
		policy: { ...policy, updatedAt: new Date().toISOString(), grants: next },
	};
}

export interface PermissionsConfigResult {
	ssh: { enabled: boolean };
	bash: { enabled: boolean };
}

interface PermissionsFile {
	version: number;
	permissions?: {
		ssh?: { enabled?: boolean };
		bash?: { enabled?: boolean };
	};
}

export async function readPermissionsConfig(projectDir: string): Promise<PermissionsConfigResult> {
	const home = process.env.HOME || homedir();
	const globalPath = join(home, ".pi", "agent", "permissions.json");
	const projectPath = join(projectDir, ".pi", "permissions.json");

	// Defaults: ssh enabled, bash disabled
	const result: PermissionsConfigResult = {
		ssh: { enabled: true },
		bash: { enabled: false },
	};

	// Try reading global config
	try {
		if (existsSync(globalPath)) {
			const raw = await readFile(globalPath, "utf-8");
			const parsed = JSON.parse(raw) as PermissionsFile;
			if (parsed?.permissions?.ssh?.enabled !== undefined) {
				result.ssh.enabled = Boolean(parsed.permissions.ssh.enabled);
			}
			if (parsed?.permissions?.bash?.enabled !== undefined) {
				result.bash.enabled = Boolean(parsed.permissions.bash.enabled);
			}
		}
	} catch {
		// Ignore errors reading global config
	}

	// Try reading project config (overrides global)
	try {
		if (existsSync(projectPath)) {
			const raw = await readFile(projectPath, "utf-8");
			const parsed = JSON.parse(raw) as PermissionsFile;
			if (parsed?.permissions?.ssh?.enabled !== undefined) {
				result.ssh.enabled = Boolean(parsed.permissions.ssh.enabled);
			}
			if (parsed?.permissions?.bash?.enabled !== undefined) {
				result.bash.enabled = Boolean(parsed.permissions.bash.enabled);
			}
		}
	} catch {
		// Ignore errors reading project config
	}

	return result;
}
