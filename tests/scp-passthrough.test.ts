import test from "node:test";
import assert from "node:assert/strict";
import { isDirectSshFamilyCommand } from "../src/ssh/matcher.ts";
import { legacyDirectSshFamilyMatchDetailed } from "../src/shell/fallback/legacy-matcher.ts";

// =============================================================================
// SCP Passthrough Tests
// SCP commands should NOT be blocked by the direct SSH matcher.
// They should pass through and trigger bash permissions approval when enabled.
// =============================================================================

test("SCP commands are NOT blocked by isDirectSshFamilyCommand", () => {
	// SCP should pass through (not be blocked)
	assert.equal(isDirectSshFamilyCommand("scp file user@host:/tmp"), false);
	assert.equal(isDirectSshFamilyCommand("scp user@host:/remote/file ./local"), false);
	assert.equal(isDirectSshFamilyCommand("scp -r directory user@host:/tmp"), false);
	assert.equal(isDirectSshFamilyCommand("scp -P 22 file user@host:/tmp"), false);
	assert.equal(isDirectSshFamilyCommand("scp -i key.pem file user@host:/tmp"), false);
});

test("SCP commands pass through legacy matcher (not blocked)", () => {
	// SCP should pass through the legacy matcher too
	const result1 = legacyDirectSshFamilyMatchDetailed("scp file user@host:/tmp");
	assert.equal(result1.blocked, false, "scp should not be blocked");

	const result2 = legacyDirectSshFamilyMatchDetailed("scp -r directory user@host:/tmp");
	assert.equal(result2.blocked, false, "scp -r should not be blocked");

	const result3 = legacyDirectSshFamilyMatchDetailed("scp user@host:/remote/file ./local");
	assert.equal(result3.blocked, false, "scp download should not be blocked");
});

test("SCP passes through with env wrappers (not blocked)", () => {
	// SCP through env wrapper should also pass through
	assert.equal(isDirectSshFamilyCommand("env FOO=bar scp file user@host:/tmp"), false);
	assert.equal(isDirectSshFamilyCommand("FOO=bar scp file user@host:/tmp"), false);
});

test("other SSH-family commands still blocked by isDirectSshFamilyCommand", () => {
	// SSH, SFTP, SSHpass, Mosh should still be blocked
	assert.equal(isDirectSshFamilyCommand("ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("sftp user@host"), true);
	assert.equal(isDirectSshFamilyCommand("sshpass -p secret ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("mosh user@host"), true);
});

test("other SSH-family commands still blocked by legacy matcher", () => {
	assert.equal(legacyDirectSshFamilyMatchDetailed("ssh user@host").blocked, true);
	assert.equal(legacyDirectSshFamilyMatchDetailed("sftp user@host").blocked, true);
	assert.equal(legacyDirectSshFamilyMatchDetailed("sshpass -p secret ssh user@host").blocked, true);
	assert.equal(legacyDirectSshFamilyMatchDetailed("mosh user@host").blocked, true);
});

test("SCP in complex commands passes through", () => {
	// SCP in various command structures should pass through
	assert.equal(isDirectSshFamilyCommand("scp file user@host:/tmp && echo done"), false);
	assert.equal(isDirectSshFamilyCommand("echo start; scp file user@host:/tmp"), false);
	assert.equal(isDirectSshFamilyCommand("scp file user@host:/tmp || echo failed"), false);
});

test("SSH near SCP doesn't cause false positive", () => {
	// Commands containing 'ssh' substring but not SSH commands should not be blocked
	assert.equal(isDirectSshFamilyCommand("echo ssh && scp file user@host:/tmp"), false);
});