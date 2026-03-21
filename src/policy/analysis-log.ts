import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { lstat, mkdir, readFile, stat, unlink, rename, open } from "node:fs/promises";
import { existsSync, constants as fsConstants, lstatSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { buildCommandPreview } from "./fingerprint.ts";

export interface AnalysisLogEntry {
	timestamp: string;
	commandPreview: string;
	target?: string;
	cwd?: string;
	patternAnalysisComplete: boolean;
	patterns: string[];
	reason?: string;
	needsImprovement: boolean;
}

let logPath: string | null = null;
let writeLock = Promise.resolve(); // Mutex for concurrent writes

/**
 * Initialize the analysis log path.
 * Rejects if the path is an existing symlink (security check).
 */
export function initAnalysisLog(storeDir: string): void {
	const path = join(storeDir, "analysis-log.jsonl");
	// Security: reject if log path exists and is a symlink
	if (existsSync(path)) {
		const lst = lstatSync(path);
		if (lst.isSymbolicLink()) {
			throw new AnalysisLogSecurityError(`Symlink paths are not allowed for analysis log: ${path}`);
		}
	}
	logPath = path;
}

export function getAnalysisLogPath(): string | null {
	return logPath;
}

/**
 * Security error class for analysis log violations.
 */
export class AnalysisLogSecurityError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "AnalysisLogSecurityError";
	}
}

/**
 * Get secure flags for opening temp files.
 * Includes O_NOFOLLOW where available to prevent symlink attacks.
 */
function secureTmpOpenFlags(): number {
	let flags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL;
	if (typeof fsConstants.O_NOFOLLOW === "number") {
		flags |= fsConstants.O_NOFOLLOW;
	}
	return flags;
}

/**
 * Generate a unique temp file name using random bytes for concurrency safety.
 */
function generateUniqueTmpPath(basePath: string): string {
	const randomSuffix = randomBytes(8).toString("hex");
	return `${basePath}.${process.pid}.${Date.now()}.${randomSuffix}.tmp`;
}

/**
 * Secure atomic write for a file.
 * Uses temp file + rename to ensure atomic writes.
 * Rejects symlinks at target path.
 * Uses O_NOFOLLOW where available to prevent symlink attacks.
 * Uses unique temp file names to handle concurrent writes safely.
 */
async function writeAtomicSecure(path: string, data: string): Promise<void> {
	// Security check: reject if path is a symlink
	if (existsSync(path)) {
		const lst = await lstat(path);
		if (lst.isSymbolicLink()) {
			throw new AnalysisLogSecurityError(`Symlink paths are not allowed: ${path}`);
		}
	}

	// Write to temp file first with O_EXCL | O_NOFOLLOW
	const tmpPath = generateUniqueTmpPath(path);
	const handle = await open(tmpPath, secureTmpOpenFlags(), 0o600);

	try {
		await handle.writeFile(data, { encoding: "utf-8" });
		await handle.sync();
		await handle.close();
	} catch (err) {
		await handle.close();
		await unlink(tmpPath).catch(() => {});
		throw err;
	}

	// Atomic rename
	try {
		await rename(tmpPath, path);
	} catch (err) {
		await unlink(tmpPath).catch(() => {});
		throw err;
	}
}

/**
 * Ensure log directory exists with secure permissions.
 * Creates directory with 0700 permissions.
 * Rejects if path is a symlink.
 */
async function ensureLogDirectory(path: string): Promise<void> {
	const dir = dirname(path);
	await mkdir(dir, { recursive: true, mode: 0o700 });

	// Verify directory is not a symlink
	try {
		const dirStat = await lstat(dir);
		if (dirStat.isSymbolicLink()) {
			throw new AnalysisLogSecurityError(`Log directory is a symlink (not allowed): ${dir}`);
		}
	} catch (e) {
		if (e instanceof AnalysisLogSecurityError) throw e;
		if ((e as { code?: string }).code !== "ENOENT") throw e;
	}
}

/**
 * Log a command that couldn't be fully analyzed or produced wildcard patterns.
 * Uses secure appends and stores only commandPreview (not full command).
 * Uses a mutex to serialize concurrent writes safely.
 *
 * @throws AnalysisLogSecurityError if security violations detected (symlinks, insecure permissions)
 */
export async function logAnalysisResult(
	command: string,
	options: {
		target?: string;
		cwd?: string;
		patternAnalysisComplete: boolean;
		patterns: string[];
		reason?: string;
	},
): Promise<void> {
	if (!logPath) return;

	const needsImprovement =
		!options.patternAnalysisComplete ||
		options.patterns.length === 0 ||
		options.patterns.every((p) => p.endsWith(" *"));

	// Don't log commands that are already perfectly analyzed
	if (!needsImprovement) return;

	// Use commandPreview only (truncated to 120 chars), not full command
	const commandPreview = buildCommandPreview(command, 120);

	const entry: AnalysisLogEntry = {
		timestamp: new Date().toISOString(),
		commandPreview,
		target: options.target,
		cwd: options.cwd,
		patternAnalysisComplete: options.patternAnalysisComplete,
		patterns: options.patterns,
		reason: options.reason,
		needsImprovement,
	};

	// Serialize writes using mutex
	await (writeLock = writeLock.then(
		async () => {
			await doLogAnalysisResult(entry);
		},
		() => {
			// If previous write failed, continue with current write
			// (suppress error to avoid noisy logging in write lock path)
		},
	));
}

/**
 * Internal function to perform the actual log write.
 * Must be called within the writeLock mutex.
 */
async function doLogAnalysisResult(entry: AnalysisLogEntry): Promise<void> {
	if (!logPath) return;

	// Ensure secure directory (throws on symlink directories)
	await ensureLogDirectory(logPath);

	// Security check: reject if log path is a symlink
	if (existsSync(logPath)) {
		const lst = await lstat(logPath);
		if (lst.isSymbolicLink()) {
			throw new AnalysisLogSecurityError(`Symlink paths are not allowed: ${logPath}`);
		}
	}

	// For JSONL, use append mode for safe concurrent writes.
	const line = JSON.stringify(entry) + "\n";

	// Use O_CREAT | O_APPEND for reliable concurrent writes
	// First write: create file atomically with secure permissions
	// Subsequent writes: append to existing file
	if (!existsSync(logPath)) {
		// First write: create file atomically with secure permissions
		await writeAtomicSecure(logPath, line);
	} else {
		// Subsequent writes: append to existing file
		const handle = await open(logPath, fsConstants.O_WRONLY | fsConstants.O_APPEND);
		try {
			// Verify it's still a regular file (not swapped to symlink)
			const s = await handle.stat();
			if (!s.isFile()) {
				throw new AnalysisLogSecurityError(`Log path is not a regular file: ${logPath}`);
			}
			await handle.writeFile(line, { encoding: "utf-8" });
			await handle.sync();
		} finally {
			await handle.close();
		}
	}
}

/**
 * Read all logged entries that need improvement.
 * Used by improvement agents to analyze patterns.
 */
export async function readEntriesNeedingImprovement(): Promise<AnalysisLogEntry[]> {
	if (!logPath) return [];

	try {
		// Security check: reject if log path is a symlink
		const lst = await lstat(logPath);
		if (lst.isSymbolicLink()) {
			return []; // Symlink not allowed
		}

		// Verify file permissions
		const s = await stat(logPath);
		if ((s.mode & 0o022) !== 0) {
			return []; // Insecure permissions
		}

		const content = await readFile(logPath, "utf-8");
		const lines = content.trim().split("\n").filter((l) => l.trim());
		const entries = lines.map((line) => JSON.parse(line) as AnalysisLogEntry);

		// Deduplicate by commandPreview, keeping most recent
		const seen = new Map<string, AnalysisLogEntry>();
		for (const entry of entries) {
			seen.set(entry.commandPreview, entry);
		}

		return Array.from(seen.values()).filter((e) => e.needsImprovement);
	} catch {
		return [];
	}
}