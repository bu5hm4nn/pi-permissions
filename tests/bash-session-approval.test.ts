import test from "node:test";
import assert from "node:assert/strict";
import { computeBashFingerprint } from "../src/policy/fingerprint.ts";
import { isBashSessionApproved } from "../src/policy/bash-session-approval.ts";

test("no-UI mode ignores exact session grant", () => {
	const command = "echo hello";
	const grants = new Set<string>([computeBashFingerprint(command)]);

	const approved = isBashSessionApproved({
		fingerprint: computeBashFingerprint(command),
		patterns: ["echo *"],
		bashSessionGrants: grants,
		hasUI: false,
	});

	assert.equal(approved, false);
});

test("UI mode still honors session grant", () => {
	const command = "echo hello";
	const grants = new Set<string>([computeBashFingerprint(command)]);

	const approved = isBashSessionApproved({
		fingerprint: computeBashFingerprint(command),
		patterns: ["echo *"],
		bashSessionGrants: grants,
		hasUI: true,
	});

	assert.equal(approved, true);
});

test("incomplete analysis must not auto-approve via reusable pattern grant", () => {
	const command = "echo hello";
	const grants = new Set<string>([computeBashFingerprint("echo *")]);

	const approved = isBashSessionApproved({
		fingerprint: computeBashFingerprint(command),
		patterns: ["echo *"],
		bashSessionGrants: grants,
		hasUI: true,
		analysisComplete: false,
	});

	assert.equal(approved, false);
});

test("incomplete analysis must not auto-approve via fallback session grant", () => {
	const command = "curl -X POST https://api.example.com/items";
	const grants = new Set<string>([computeBashFingerprint("curl POST *")]);

	const approved = isBashSessionApproved({
		fingerprint: computeBashFingerprint(command),
		patterns: ["curl POST https://api.example.com/items"],
		bashSessionGrants: grants,
		hasUI: true,
		analysisComplete: false,
	});

	assert.equal(approved, false);
});

test("complete analysis still auto-approves via reusable pattern grant", () => {
	const command = "echo hello";
	const grants = new Set<string>([computeBashFingerprint("echo *")]);

	const approved = isBashSessionApproved({
		fingerprint: computeBashFingerprint(command),
		patterns: ["echo *"],
		bashSessionGrants: grants,
		hasUI: true,
		analysisComplete: true,
	});

	assert.equal(approved, true);
});
