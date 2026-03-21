/**
 * TDD RED tests for isReusableUnsafe function in src/policy/fingerprint.ts
 *
 * Requirements:
 * Commands are "reusable-unsafe" if they:
 * - Reference relative paths (./ or ../) - these are cwd-dependent
 * - Use variable interpolation that we can't resolve
 * - Contain dynamic elements that make the fingerprint unstable
 *
 * Key behavior:
 * - isReusableUnsafe('echo hi', '/home/user/myproject', true) === true  -- cwd provided makes it unsafe EVEN with patternAnalysisComplete
 * - isReusableUnsafe('echo hi', '/home/user/myproject', false) === true -- cwd provided, pattern analysis incomplete
 * - isReusableUnsafe('echo hi', undefined, true) === false -- pattern analysis complete, no cwd
 * - isReusableUnsafe('./script.sh', undefined, true) === true -- relative path makes it unsafe regardless
 */
import test from "node:test";
import assert from "node:assert/strict";
import { isReusableUnsafe } from "../src/policy/fingerprint.ts";

// =============================================================================
// Test cases from PR #5 review requirements
// =============================================================================

test("isReusableUnsafe returns true when cwd is provided even with patternAnalysisComplete=true", () => {
	// REVIEW REQUIREMENT: cwd makes it unsafe for reusable approvals even with complete analysis
	const result = isReusableUnsafe("echo hi", "/home/user/myproject", true);
	assert.equal(
		result,
		true,
		"Expected cwd + patternAnalysisComplete=true to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe returns true when cwd is provided with patternAnalysisComplete=false", () => {
	// REVIEW REQUIREMENT: cwd provided, pattern analysis incomplete = unsafe
	const result = isReusableUnsafe("echo hi", "/home/user/myproject", false);
	assert.equal(
		result,
		true,
		"Expected cwd + patternAnalysisComplete=false to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe returns false when no cwd and patternAnalysisComplete=true", () => {
	// REVIEW REQUIREMENT: complete pattern analysis, no cwd = safe for reuse
	const result = isReusableUnsafe("echo hi", undefined, true);
	assert.equal(
		result,
		false,
		"Expected no cwd + patternAnalysisComplete=true to return false (safe for reuse)",
	);
});

test("isReusableUnsafe returns true for relative paths even with patternAnalysisComplete=true", () => {
	// REVIEW REQUIREMENT: relative paths are always unsafe for reuse
	const result = isReusableUnsafe("./script.sh", undefined, true);
	assert.equal(
		result,
		true,
		"Expected relative path ./script.sh to return true (unsafe for reuse)",
	);
});

// =============================================================================
// Additional test coverage for isReusableUnsafe edge cases
// =============================================================================

test("isReusableUnsafe returns true for .. relative paths", () => {
	const result = isReusableUnsafe("../script.sh", undefined, true);
	assert.equal(
		result,
		true,
		"Expected relative path ../script.sh to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe returns true for ./embedded in command", () => {
	const result = isReusableUnsafe("bash ./scripts/build.sh", undefined, true);
	assert.equal(
		result,
		true,
		"Expected command with ./embedded path to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe returns true for ../embedded in command", () => {
	const result = isReusableUnsafe("cat ../config/settings.json", undefined, true);
	assert.equal(
		result,
		true,
		"Expected command with ../embedded path to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe returns false for absolute paths with patternAnalysisComplete=true and no cwd", () => {
	const result = isReusableUnsafe("/usr/bin/env node", undefined, true);
	assert.equal(
		result,
		false,
		"Expected absolute path with no cwd and patternAnalysisComplete to return false (safe for reuse)",
	);
});

test("isReusableUnsafe default parameters behave correctly", () => {
	// When called with only command, cwd defaults to undefined and patternAnalysisComplete defaults to undefined
	// This should be safe if no relative paths and no cwd
	const result = isReusableUnsafe("echo hello world");
	assert.equal(
		result,
		false,
		"Expected simple command with defaults to return false (safe for reuse)",
	);
});

test("isReusableUnsafe with relative path after semicolon", () => {
	// Relative paths anywhere in command make it unsafe
	const result = isReusableUnsafe("echo hi; ./test.sh", undefined, true);
	assert.equal(
		result,
		true,
		"Expected command with relative path after semicolon to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe with relative path after pipe", () => {
	const result = isReusableUnsafe("cat file | ./process.sh", undefined, true);
	assert.equal(
		result,
		true,
		"Expected command with relative path after pipe to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe with relative path after &&", () => {
	const result = isReusableUnsafe("mkdir build && ./scripts/test.sh", undefined, true);
	assert.equal(
		result,
		true,
		"Expected command with relative path after && to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe with relative path after newline", () => {
	const result = isReusableUnsafe("echo 'multi\nline ./script.sh'", undefined, true);
	// This tests if newlines are handled in normalization
	assert.equal(
		result,
		true,
		"Expected command with relative path after newline to return true (unsafe for reuse)",
	);
});

test("isReusableUnsafe false positive check: dot files are not relative paths", () => {
	// Filenames starting with dot are NOT relative paths (./)
	// .gitignore, .env, etc. should NOT trigger unsafe
	const result = isReusableUnsafe("cat .gitignore", undefined, true);
	assert.equal(
		result,
		false,
		"Expected .gitignore (dot file) to NOT be treated as relative path",
	);
});

test("isReusableUnsafe with empty cwd string", () => {
	// Empty cwd string should be treated as no cwd
	const result = isReusableUnsafe("echo hi", "", true);
	assert.equal(
		result,
		false,
		"Expected empty cwd string to be treated as no cwd (safe for reuse)",
	);
});

test("isReusableUnsafe with whitespace-only cwd string", () => {
	// Whitespace-only cwd should be treated as no cwd
	const result = isReusableUnsafe("echo hi", "   ", true);
	assert.equal(
		result,
		false,
		"Expected whitespace-only cwd to be treated as no cwd (safe for reuse)",
	);
});