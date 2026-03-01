import test from "node:test";
import assert from "node:assert/strict";
import { parseShell } from "../src/shell/parser/parse.ts";
import { walkShellAst } from "../src/shell/parser/ast-walk.ts";
import { resolveHeadFromLiterals } from "../src/shell/parser/resolve-head.ts";
import { SSH_MATCHER_WRAPPERS, STANDARD_WRAPPERS } from "../src/shell/parser/wrappers.ts";

test("resolveHeadFromLiterals can normalize wrapper-resolved executable to lowercase", () => {
	const resolved = resolveHeadFromLiterals("sudo", ["--", "/usr/bin/SSH", "user@host"], SSH_MATCHER_WRAPPERS, {
		lowercase: true,
	});
	assert.equal(resolved.complete, true);
	assert.equal(resolved.head, "ssh");
	assert.equal(resolved.argIndex, 2);
});

test("resolveHeadFromLiterals preserves existing command-pattern resolution semantics", () => {
	const resolved = resolveHeadFromLiterals("env", ["FOO=bar", "docker", "ps"], STANDARD_WRAPPERS);
	assert.equal(resolved.complete, true);
	assert.equal(resolved.head, "docker");
	assert.equal(resolved.argIndex, 2);
});

test("parseShell + walkShellAst traverses shell command nodes in order", () => {
	const parsed = parseShell("echo one && cat /etc/hosts");
	assert.equal(parsed.certainty, "resolved");
	assert.ok(parsed.ast);

	const visited: string[] = [];
	walkShellAst(parsed.ast, {
		onCommand(commandNode) {
			if (commandNode?.name?.text) visited.push(commandNode.name.text);
		},
	});

	assert.deepEqual(visited, ["echo", "cat"]);
});

test("walkShellAst reports unknown node types without throwing", () => {
	const seenUnknown: string[] = [];
	walkShellAst({ type: "Script", commands: [{ type: "TotallyUnknownNode", payload: 1 }] }, {
		onUnknown(type) {
			seenUnknown.push(type);
		},
	});
	assert.deepEqual(seenUnknown, ["TotallyUnknownNode"]);
});
