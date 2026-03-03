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
