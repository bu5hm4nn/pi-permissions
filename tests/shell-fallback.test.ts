import test from "node:test";
import assert from "node:assert/strict";
import {
	stripHeredocBodiesForLegacyParsing,
	legacySplitCommandSegments,
	legacyTokenizeSegment,
	legacyDirectSshFamilyMatch,
} from "../src/shell/fallback/legacy-matcher.ts";
import { DIRECT_SSH_PARSE_FAILURE_MODE, isDirectSshFamilyCommand } from "../src/shell/analyzers/direct-ssh.ts";

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

test("direct-ssh analyzer is strict on parse-failure by default", () => {
	assert.equal(DIRECT_SSH_PARSE_FAILURE_MODE, "strict");

	const heredocScript = String.raw`python3 - <<'PY'
from pathlib import Path
print('hello')
PY`;
	assert.equal(isDirectSshFamilyCommand(heredocScript), true);
});
