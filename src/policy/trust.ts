import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS, existsSync } from "node:fs";
import { lstat, mkdir, open, readFile, realpath, rename, stat, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { TrustFile } from "./schema.ts";
import { emptyTrustFile } from "./schema.ts";

const MAX_TRUST_BYTES = 512 * 1024;

export function getTrustPath(): string {
	return join(process.env.HOME || "", ".pi", "agent", "ssh-policy-trust.json");
}

async function assertSecure(path: string) {
	const lst = await lstat(path);
	if (lst.isSymbolicLink()) throw new Error(`Symlink trust path not allowed: ${path}`);
	const s = await stat(path);
	if ((s.mode & 0o022) !== 0) throw new Error(`Insecure trust file permissions: ${path}`);
	if (typeof process.getuid === "function" && s.uid !== process.getuid()) {
		throw new Error(`Trust file owner mismatch: ${path}`);
	}
	if (s.size > MAX_TRUST_BYTES) throw new Error("trust file too large");
}

function hashProjectRoot(projectRootRealpath: string): string {
	return createHash("sha256").update(projectRootRealpath).digest("hex");
}

function requireString(value: unknown, field: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(`Invalid trust file schema: ${field} must be a non-empty string`);
	}
	return value;
}

export async function readTrust(): Promise<TrustFile> {
	const path = getTrustPath();
	if (!existsSync(path)) return emptyTrustFile();
	await assertSecure(path);
	const raw = await readFile(path, "utf-8");
	const parsed = JSON.parse(raw) as TrustFile;
	if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.trustedProjects)) {
		throw new Error("Invalid trust file schema");
	}

	const deduped = new Map<string, TrustFile["trustedProjects"][number]>();
	for (let i = 0; i < parsed.trustedProjects.length; i++) {
		const entry = parsed.trustedProjects[i] as any;
		if (!entry || typeof entry !== "object") {
			throw new Error(`Invalid trust file schema: trustedProjects[${i}]`);
		}
		const projectId = requireString(entry.projectId, `trustedProjects[${i}].projectId`);
		const projectRootRealpath = requireString(entry.projectRootRealpath, `trustedProjects[${i}].projectRootRealpath`);
		const createdAt = requireString(entry.createdAt, `trustedProjects[${i}].createdAt`);
		const canonical = await realpath(projectRootRealpath);
		if (canonical !== projectRootRealpath) {
			throw new Error(`Trust invariant violation: projectRootRealpath is not canonical for projectId ${projectId}`);
		}
		if (projectId !== hashProjectRoot(projectRootRealpath)) {
			throw new Error(`Trust invariant violation: projectId hash mismatch for ${projectRootRealpath}`);
		}
		if (!deduped.has(projectId)) {
			deduped.set(projectId, { projectId, projectRootRealpath, createdAt });
		}
	}

	return {
		version: 1,
		updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : new Date().toISOString(),
		trustedProjects: Array.from(deduped.values()),
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

async function writeTrust(path: string, trust: TrustFile): Promise<void> {
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });
	if (existsSync(path)) await assertSecure(path);
	await writeAtomicSecure(path, JSON.stringify(trust, null, 2));
}

export async function isProjectTrusted(projectId: string): Promise<boolean> {
	const trust = await readTrust();
	return trust.trustedProjects.some((p) => p.projectId === projectId);
}

export async function trustProject(projectId: string, projectRootRealpath: string): Promise<void> {
	const canonical = await realpath(projectRootRealpath);
	if (canonical !== projectRootRealpath) {
		throw new Error("Trust project root must be canonical realpath");
	}
	if (projectId !== hashProjectRoot(projectRootRealpath)) {
		throw new Error("Trust projectId does not match project root hash");
	}

	const path = getTrustPath();
	const trust = await readTrust();
	if (!trust.trustedProjects.some((p) => p.projectId === projectId)) {
		trust.trustedProjects.push({
			projectId,
			projectRootRealpath,
			createdAt: new Date().toISOString(),
		});
		trust.updatedAt = new Date().toISOString();
		await writeTrust(path, trust);
	}
}

export async function untrustProject(projectId: string): Promise<void> {
	const path = getTrustPath();
	const trust = await readTrust();
	trust.trustedProjects = trust.trustedProjects.filter((p) => p.projectId !== projectId);
	trust.updatedAt = new Date().toISOString();
	await writeTrust(path, trust);
}

export async function listTrustedProjects(): Promise<TrustFile["trustedProjects"]> {
	return (await readTrust()).trustedProjects;
}
