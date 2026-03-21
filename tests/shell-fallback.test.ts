import test from "node:test";
import assert from "node:assert/strict";
import {
	stripHeredocBodiesForLegacyParsing,
	legacySplitCommandSegments,
	legacyTokenizeSegment,
	legacyDirectSshFamilyMatch,
} from "../src/shell/fallback/legacy-matcher.ts";
import { isDirectSshFamilyCommand } from "../src/shell/analyzers/direct-ssh.ts";

test("legacy heredoc stripping removes heredoc bodies and delimiters", () => {
	const source = "cat <<'EOF'\nssh user@host\nEOF\necho ok";
	assert.equal(stripHeredocBodiesForLegacyParsing(source), "cat <<'EOF'\necho ok");
});

test("legacy segment/token contracts remain deterministic", () => {
	assert.deepEqual(legacySplitCommandSegments("echo ok && ssh user@host"), ["echo ok", "ssh user@host"]);
	assert.equal(legacySplitCommandSegments("echo ok &&"), null);
	assert.deepEqual(legacyTokenizeSegment("env FOO='x y' ssh user@host"), ["env", "FOO='x y'", "ssh", "user@host"]);
});

test("legacy matcher remains conservative", () => {
	assert.equal(legacyDirectSshFamilyMatch("echo ok"), false);
	assert.equal(legacyDirectSshFamilyMatch("sudo -- ssh user@host"), true);
	assert.equal(legacyDirectSshFamilyMatch("echo 'unterminated"), true);
});

// direct-ssh analyzer uses legacy matcher for parser-uncertain cases
// FAIL-CLOSED: Parser-uncertain cases are blocked even without SSH detected
test("direct-ssh analyzer blocks heredocs without SSH (fail-closed)", () => {
	const heredocScript = String.raw`python3 - <<'PY'
from pathlib import Path
print('hello')
PY`;
	// Parser can't build AST, fail-closed behavior blocks because we can't confirm no SSH
	assert.equal(isDirectSshFamilyCommand(heredocScript), true);
});

// Issue #4 fix: SSH keyword in heredoc body is not detected (heredoc stripped)
// FAIL-CLOSED: Parser-uncertain cases are blocked, regardless of SSH in heredoc body
test("direct-ssh analyzer blocks heredoc with SSH in body (fail-closed)", () => {
	const heredocWithSsh = String.raw`python3 - <<'PY'
import subprocess
subprocess.run(["ssh", "user@host"])
PY`;
	// Parser-uncertain cases are blocked (fail-closed)
	// SSH in Python code inside heredoc is irrelevant - we can't confirm no SSH
	assert.equal(isDirectSshFamilyCommand(heredocWithSsh), true);
});

test("direct-ssh analyzer blocks heredoc with SSH in actual command", () => {
	// SSH in the actual command (outside heredoc) should still be blocked
	const heredocWithSsh = String.raw`ssh user@host <<'EOF'
some data
EOF`;
	assert.equal(isDirectSshFamilyCommand(heredocWithSsh), true);
});