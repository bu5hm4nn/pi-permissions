import test from "node:test";
import assert from "node:assert/strict";
import { handleToolCallGuard, handleUserBashGuard } from "../src/ssh/guard.ts";
import { DIRECT_SSH_PARSE_FAILURE_MODE, isDirectSshFamilyCommand } from "../src/shell/analyzers/direct-ssh.ts";

const uncertainHeredoc = String.raw`python3 - <<'PY'
from pathlib import Path
print('hello')
PY`;

test("default runtime mode is strict", () => {
	assert.equal(DIRECT_SSH_PARSE_FAILURE_MODE, "strict");
});

test("tool_call guard blocks parser-uncertain command by default", async () => {
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: uncertainHeredoc } },
		{
			guardHealthy: true,
			matchDirectSsh: isDirectSshFamilyCommand,
		},
	);
	assert.deepEqual(result, { block: true, reason: "Direct SSH-family commands are blocked. Use ssh_bash." });
});

test("user_bash guard blocks parser-uncertain command by default", async () => {
	const result = await handleUserBashGuard(
		{ command: uncertainHeredoc },
		{
			guardHealthy: true,
			matchDirectSsh: isDirectSshFamilyCommand,
		},
	);
	assert.equal(result?.result?.exitCode, 126);
	assert.match(result?.result?.output || "", /direct SSH-family commands are disabled/i);
});

test("default matcher still blocks direct ssh-family commands", () => {
	assert.equal(isDirectSshFamilyCommand("ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("sudo -- ssh user@host"), true);
});
