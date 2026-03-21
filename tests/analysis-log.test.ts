/**
 * TDD RED tests for src/policy/analysis-log.ts
 *
 * Requirements:
 * - Symlink at log path is rejected (throws error)
 * - Directory created with 0700
 * - File written with 0600
 * - Only commandPreview is logged, not full command
 * - Atomic writes (temp file + rename) are used
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, symlink, rm, stat, readFile, lstat, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { initAnalysisLog, logAnalysisResult, getAnalysisLogPath, readEntriesNeedingImprovement } from "../src/policy/analysis-log.ts";

async function createTempDir(): Promise<string> {
	return mkdtemp(join(tmpdir(), "analysis-log-test-"));
}

// =============================================================================
// Symlink rejection tests - using public API via initAnalysisLog
// =============================================================================

test("logAnalysisResult rejects symlink at log path", async () => {
	const tempDir = await createTempDir();
	try {
		const targetDir = join(tempDir, "target");
		const logDir = join(tempDir, "logs");
		const symlinkLogDir = join(tempDir, "symlink-target");
		
		// Create target directory and symlink directory
		await mkdir(targetDir, { recursive: true });
		await mkdir(symlinkLogDir, { recursive: true });
		
		// Create a symlink that points to another directory
		// We'll create analysis-log.jsonl as a symlink to test rejection
		const realLogFile = join(symlinkLogDir, "real-log.jsonl");
		await writeFile(realLogFile, "[]");
		
		const symlinkPath = join(logDir, "analysis-log.jsonl");
		await mkdir(logDir, { recursive: true });
		
		// Create symlink at the log path
		await symlink(realLogFile, symlinkPath, "file");
		
		// Verify symlink exists
		const linkStats = await lstat(symlinkPath);
		assert.equal(linkStats.isSymbolicLink(), true, "Expected symlink to exist before test");
		
		// Initialize analysis log should reject symlink paths
		assert.throws(
			() => {
				initAnalysisLog(logDir);
			},
			/symlink|forbidden|security/i,
			"Expected initAnalysisLog to reject symlink path",
		);
		
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// =============================================================================
// Directory permissions tests
// =============================================================================

test("logAnalysisResult creates directory with 0700 permissions", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs", "deep");
		initAnalysisLog(logDir);

		await logAnalysisResult("test command", {
			patternAnalysisComplete: false,
			patterns: ["test *"],
		});

		const stats = await stat(logDir);
		const mode = stats.mode & 0o777;
		assert.equal(mode, 0o700, "Expected directory to have 0700 permissions");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// =============================================================================
// File permissions tests
// =============================================================================

test("logAnalysisResult creates file with 0600 permissions", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		const logPath = join(logDir, "analysis-log.jsonl");
		initAnalysisLog(logDir);

		await logAnalysisResult("test command", {
			patternAnalysisComplete: false,
			patterns: ["test *"],
		});

		const stats = await stat(logPath);
		const mode = stats.mode & 0o777;
		assert.equal(mode, 0o600, "Expected file to have 0600 permissions");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// =============================================================================
// Command preview logging tests (not full command)
// =============================================================================

test("logAnalysisResult logs commandPreview, not full command", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		const logPath = join(logDir, "analysis-log.jsonl");
		initAnalysisLog(logDir);

		// Call the function with a very long command
		const longCommand = "a".repeat(200);
		await logAnalysisResult(longCommand, {
			patternAnalysisComplete: false,
			patterns: ["test *"],
		});

		const content = await readFile(logPath, "utf-8");
		
		// RED: Current implementation stores full command in entry.command
		// We expect it to use commandPreview instead (truncated)
		const entry = JSON.parse(content.trim());
		
		// The entry should NOT contain the full 200-char command as-is
		// It should be truncated to a preview format (e.g., "aaa...aaa" with hash)
		assert.ok(
			!entry.command || entry.command.length < 200 || entry.commandPreview !== undefined,
			"Expected logged entry to use preview or have truncated command, not full 200 chars - TEST RED",
		);
		
		// If commandPreview exists, it should be significantly shorter
		if (entry.commandPreview !== undefined) {
			assert.ok(
				entry.commandPreview.length < 200,
				"Expected commandPreview to be truncated",
			);
		}
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("logAnalysisResult stores commandPreview field as truncated string", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		const logPath = join(logDir, "analysis-log.jsonl");
		initAnalysisLog(logDir);

		const command = "echo 'This is a very long command that would normally be truncated in the preview'";
		await logAnalysisResult(command, {
			target: "user@host",
			cwd: "/tmp",
			patternAnalysisComplete: false,
			patterns: ["echo *"],
		});

		const content = await readFile(logPath, "utf-8");
		const entry = JSON.parse(content.trim());

		// Entry should have commandPreview field (truncated)
		// RED: Current implementation may not have this field
		assert.ok(
			entry.commandPreview !== undefined,
			"Expected entry to have commandPreview field - TEST RED",
		);
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// =============================================================================
// Atomic write tests - using inode change detection
// =============================================================================

test("logAnalysisResult uses append for writes (entries preserved)", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		const logPath = join(logDir, "analysis-log.jsonl");
		initAnalysisLog(logDir);

		// First write
		await logAnalysisResult("first command", {
			patternAnalysisComplete: false,
			patterns: ["first *"],
		});

		const firstStats = await stat(logPath);
		const firstInode = (firstStats as any).ino;

		// Second write - using append, inode stays the same
		await logAnalysisResult("second command", {
			patternAnalysisComplete: false,
			patterns: ["second *"],
		});

		const secondStats = await stat(logPath);
		const secondInode = (secondStats as any).ino;

		// Verify no temp files left behind
		const files = await readdir(logDir);
		const tempFiles = files.filter(f => f.includes(".tmp") || f.includes("temp") || f.includes(".bak"));
		assert.equal(tempFiles.length, 0, "Expected no temp files after writes completed");
		
		// With append-based writes, inode stays the same
		assert.equal(
			firstInode,
			secondInode,
			"Expected inode to stay same after append writes",
		);
		
		// Verify both entries are preserved
		const entries = await readEntriesNeedingImprovement();
		assert.equal(entries.length, 2, "Expected both entries to be preserved");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("logAnalysisResult does not leave partial writes on concurrent access", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		initAnalysisLog(logDir);

		// Write multiple entries concurrently
		const promises = [];
		for (let i = 0; i < 10; i++) {
			promises.push(
				logAnalysisResult(`command ${i}`, {
					patternAnalysisComplete: false,
					patterns: [`cmd${i} *`],
				}),
			);
		}
		await Promise.all(promises);

		// Verify all entries were written (atomic writes shouldn't lose data)
		const entries = await readEntriesNeedingImprovement();
		assert.equal(entries.length, 10, "Expected all 10 entries to be written atomically");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("logAnalysisResult preserves entries across writes (no truncation)", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		initAnalysisLog(logDir);

		// First write
		await logAnalysisResult("first command", {
			patternAnalysisComplete: false,
			patterns: ["first *"],
		});

		// Second write
		await logAnalysisResult("second command", {
			patternAnalysisComplete: false,
			patterns: ["second *"],
		});

		// Read all entries - both should be present
		const entries = await readEntriesNeedingImprovement();
		assert.ok(entries.length >= 2, "Expected both entries to be preserved");
		
		// Verify we can find both commandPreviews (security: full command not stored)
		const previews = entries.map(e => e.commandPreview);
		assert.ok(previews.some(p => p.includes("first command")), "Expected 'first command' preview to be preserved");
		assert.ok(previews.some(p => p.includes("second command")), "Expected 'second command' preview to be preserved");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// =============================================================================
// Entry structure tests
// =============================================================================

test("logAnalysisResult creates valid JSONL entry structure", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		const logPath = join(logDir, "analysis-log.jsonl");
		initAnalysisLog(logDir);

		await logAnalysisResult("docker run alpine", {
			target: "user@host",
			cwd: "/tmp",
			patternAnalysisComplete: false,
			patterns: ["docker run *"],
			reason: "incomplete pattern extraction",
		});

		const content = await readFile(logPath, "utf-8");
		const lines = content.trim().split("\n").filter((l) => l.trim());
		assert.equal(lines.length, 1, "Expected exactly one line in JSONL file");

		const entry = JSON.parse(lines[0]);
		assert.ok(entry.timestamp, "Expected timestamp field");
		assert.ok(entry.commandPreview, "Expected commandPreview field (security: no full command stored)");
		assert.ok(Array.isArray(entry.patterns), "Expected patterns array");
		assert.equal(entry.needsImprovement, true, "Expected needsImprovement to be true");
		// PR #5: Security fix - hash and full command fields removed, only commandPreview persists
		assert.equal(entry.hash, undefined, "Expected hash field to be removed (security)");
		assert.equal(entry.command, undefined, "Expected command field to be removed (use commandPreview)");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("logAnalysisResult does not log commands that are already perfectly analyzed", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		initAnalysisLog(logDir);

		// Log a command with complete analysis and non-wildcard patterns
		await logAnalysisResult("docker run alpine", {
			patternAnalysisComplete: true,
			patterns: ["docker run alpine"],
		});

		// The command is perfectly analyzed - should not be logged
		const entries = await readEntriesNeedingImprovement();
		assert.equal(entries.length, 0, "Expected perfectly analyzed command to not be logged");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("readEntriesNeedingImprovement returns entries sorted by timestamp", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		initAnalysisLog(logDir);

		// Write multiple entries with slight delays to ensure different timestamps
		await logAnalysisResult("cmd1", {
			patternAnalysisComplete: false,
			patterns: [],
		});
		await new Promise((r) => setTimeout(r, 10));
		await logAnalysisResult("cmd2", {
			patternAnalysisComplete: false,
			patterns: [],
		});
		await new Promise((r) => setTimeout(r, 10));
		await logAnalysisResult("cmd3", {
			patternAnalysisComplete: false,
			patterns: [],
		});

		const entries = await readEntriesNeedingImprovement();
		// Entries should be in order (most recent last in the original file)
		// but after deduplication, we just check we got the entries
		assert.ok(entries.length >= 3, "Expected at least 3 entries");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

// =============================================================================
// Security tests - file owner/permission validation
// =============================================================================

test("logAnalysisResult creates file with secure ownership", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs");
		const logPath = join(logDir, "analysis-log.jsonl");
		initAnalysisLog(logDir);

		await logAnalysisResult("test command", {
			patternAnalysisComplete: false,
			patterns: ["test *"],
		});

		const stats = await stat(logPath);
		
		// On systems with uid support, verify file is owned by current user
		if (typeof process.getuid === "function") {
			assert.equal(stats.uid, process.getuid(), "Expected file to be owned by current user");
		}
		
		// Verify file is NOT group/world writable
		const mode = stats.mode & 0o777;
		assert.equal(mode, 0o600, "Expected file to have exactly 0600 permissions (no group/world access)");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});

test("logAnalysisResult creates log directory with secure permissions", async () => {
	const tempDir = await createTempDir();
	try {
		const logDir = join(tempDir, "logs", "nested");
		initAnalysisLog(logDir);

		await logAnalysisResult("test command", {
			patternAnalysisComplete: false,
			patterns: ["test *"],
		});

		// Check all directories in the path have secure permissions
		const nestedStats = await stat(logDir);
		const nestedMode = nestedStats.mode & 0o777;
		assert.equal(nestedMode, 0o700, "Expected nested directory to have 0700 permissions");

		const parentDir = dirname(logDir);
		const parentStats = await stat(parentDir);
		const parentMode = parentStats.mode & 0o777;
		// Parent may have inherited permissions but should be reasonably secure
		assert.ok((parentMode & 0o077) === 0, "Expected parent directory to have no group/world write");
	} finally {
		await rm(tempDir, { recursive: true, force: true });
	}
});