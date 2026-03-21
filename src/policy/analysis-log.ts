import { appendFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { createHash } from "node:crypto";

export interface AnalysisLogEntry {
	timestamp: string;
	hash: string;
	command: string;
	target?: string;
	cwd?: string;
	patternAnalysisComplete: boolean;
	patterns: string[];
	reason?: string;
	needsImprovement: boolean;
}

let logPath: string | null = null;

export function initAnalysisLog(storeDir: string): void {
	logPath = join(storeDir, "analysis-log.jsonl");
}

export function getAnalysisLogPath(): string | null {
	return logPath;
}

/**
 * Compute a stable hash for deduplication - same command gets same hash
 */
function computeCommandHash(command: string, target?: string, cwd?: string): string {
	const material = `${target ?? ""}|${cwd ?? ""}|${command}`;
	return createHash("sha256").update(material).digest("hex").slice(0, 16);
}

/**
 * Log a command that couldn't be fully analyzed or produced wildcard patterns.
 * Used to feed a future agent that improves pattern extraction.
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

	try {
		const needsImprovement =
			!options.patternAnalysisComplete ||
			options.patterns.length === 0 ||
			options.patterns.every((p) => p.endsWith(" *"));

		// Don't log commands that are already perfectly analyzed
		if (!needsImprovement) return;

		const entry: AnalysisLogEntry = {
			timestamp: new Date().toISOString(),
			hash: computeCommandHash(command, options.target, options.cwd),
			command,
			target: options.target,
			cwd: options.cwd,
			patternAnalysisComplete: options.patternAnalysisComplete,
			patterns: options.patterns,
			reason: options.reason,
			needsImprovement,
		};

		await mkdir(dirname(logPath), { recursive: true, mode: 0o700 });
		await appendFile(logPath, JSON.stringify(entry) + "\n");
	} catch {
		// Silently ignore logging failures
	}
}

/**
 * Read all logged entries that need improvement.
 * Used by improvement agents to analyze patterns.
 */
export async function readEntriesNeedingImprovement(): Promise<AnalysisLogEntry[]> {
	if (!logPath) return [];

	try {
		const { readFile } = await import("node:fs/promises");
		const content = await readFile(logPath, "utf-8");
		const lines = content.trim().split("\n").filter((l) => l.trim());
		const entries = lines.map((line) => JSON.parse(line) as AnalysisLogEntry);

		// Deduplicate by hash, keeping most recent
		const seen = new Map<string, AnalysisLogEntry>();
		for (const entry of entries) {
			seen.set(entry.hash, entry);
		}

		return Array.from(seen.values()).filter((e) => e.needsImprovement);
	} catch {
		return [];
	}
}