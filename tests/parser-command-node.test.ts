import test from "node:test";
import assert from "node:assert/strict";
import { extractLiteralCommandNodeParts } from "../src/shell/parser/command-node.ts";

test("extractLiteralCommandNodeParts returns head and literal suffix words", () => {
	const commandNode = {
		type: "Command",
		name: { type: "Word", text: "env", expansion: [] },
		suffix: [
			{ type: "Word", text: "FOO=bar", expansion: [] },
			{ type: "Word", text: "docker", expansion: [] },
			{ type: "Word", text: "ps", expansion: [] },
		],
	};

	const extracted = extractLiteralCommandNodeParts(commandNode);
	assert.equal(extracted.complete, true);
	assert.equal(extracted.headText, "env");
	assert.deepEqual(extracted.suffixLiterals, ["FOO=bar", "docker", "ps"]);
});

test("extractLiteralCommandNodeParts is incomplete for non-literal command name", () => {
	const commandNode = {
		type: "Command",
		name: { type: "Word", text: "$RUNNER", expansion: [{ type: "ParameterExpansion", parameter: "RUNNER" }] },
		suffix: [],
	};

	const extracted = extractLiteralCommandNodeParts(commandNode);
	assert.equal(extracted.complete, false);
	assert.equal(extracted.headText, "");
	assert.deepEqual(extracted.suffixLiterals, []);
});

test("extractLiteralCommandNodeParts is incomplete when a suffix word is non-literal", () => {
	const commandNode = {
		type: "Command",
		name: { type: "Word", text: "echo", expansion: [] },
		suffix: [
			{ type: "Word", text: "ok", expansion: [] },
			{ type: "Word", text: "$(whoami)", expansion: [{ type: "CommandExpansion" }] },
		],
	};

	const extracted = extractLiteralCommandNodeParts(commandNode);
	assert.equal(extracted.complete, false);
	assert.equal(extracted.headText, "");
	assert.deepEqual(extracted.suffixLiterals, []);
});
