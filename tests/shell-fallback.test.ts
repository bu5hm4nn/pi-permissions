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

// direct-ssh analyzer passes through parse failures without detected SSH
// (flows to bash permissions logic instead of fake "SSH blocked" error)
test("direct-ssh analyzer allows parse failures without SSH (flows to bash permissions)", () => {
	const heredocScript = String.raw`python3 - <<'PY'
from pathlib import Path
print('hello')
PY`;
	assert.equal(isDirectSshFamilyCommand(heredocScript), false);
});

// Issue #4 fix: SSH keyword in heredoc body should NOT cause false block
test("direct-ssh analyzer does not false-block on SSH in heredoc body (legacy path uses sanitized)", () => {
	const heredocWithSsh = String.raw`python3 - <<'PY'
import subprocess
subprocess.run(["ssh", "user@host"])
PY`;
	// After heredoc stripping, the script becomes "python3 - <<'PY'" with no SSH
	// So this should NOT be blocked even though 'ssh' appears in the heredoc body
	assert.equal(isDirectSshFamilyCommand(heredocWithSsh), false);
});

test("direct-ssh analyzer blocks heredoc with SSH in actual command", () => {
	// SSH in the actual command (outside heredoc) should still be blocked
	const heredocWithSsh = String.raw`ssh user@host <<'EOF'
some data
EOF`;
	assert.equal(isDirectSshFamilyCommand(heredocWithSsh), true);
});
