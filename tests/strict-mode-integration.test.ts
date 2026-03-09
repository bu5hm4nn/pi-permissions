import test from "node:test";
import assert from "node:assert/strict";
import { handleToolCallGuard, handleUserBashGuard } from "../src/ssh/guard.ts";
import { isDirectSshFamilyCommand } from "../src/shell/analyzers/direct-ssh.ts";

const uncertainHeredoc = String.raw`python3 - <<'PY'
from pathlib import Path
print('hello')
PY`;

// Parser-uncertain commands WITHOUT SSH should pass through to bash permissions logic,
// not be blocked with a fake "SSH blocked" error.
test("tool_call guard allows parser-uncertain command when bash permissions disabled", async () => {
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: uncertainHeredoc } },
		{
			guardHealthy: true,
			matchDirectSsh: isDirectSshFamilyCommand,
			// bash permissions disabled (default) - should pass through
		},
	);
	// Should pass through (undefined result) since no SSH detected and bash permissions disabled
	assert.equal(result, undefined);
});

test("user_bash guard allows parser-uncertain command when bash permissions disabled", async () => {
	const result = await handleUserBashGuard(
		{ command: uncertainHeredoc },
		{
			guardHealthy: true,
			matchDirectSsh: isDirectSshFamilyCommand,
			// bash permissions disabled (default) - should pass through
		},
	);
	// Should pass through (undefined result) since no SSH detected
	assert.equal(result, undefined);
});

test("default matcher still blocks direct ssh-family commands", () => {
	assert.equal(isDirectSshFamilyCommand("ssh user@host"), true);
	assert.equal(isDirectSshFamilyCommand("sudo -- ssh user@host"), true);
});