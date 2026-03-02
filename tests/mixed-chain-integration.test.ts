import test from "node:test";
import assert from "node:assert/strict";
import { analyzeCommandPatterns } from "../src/policy/command-patterns.ts";

test("integration: mixed curl and wget URL scopes are correctly separated", () => {
	const cmd = "curl -X POST https://api.example.com/c -d 'foo' && wget --method=DELETE https://api.example.com/w";
	const analysis = analyzeCommandPatterns(cmd);
	
	assert.equal(analysis.complete, true);
	assert.ok(analysis.patterns.includes("curl POST https://api.example.com/c"), "Should include curl pattern");
	assert.ok(analysis.patterns.includes("wget DELETE https://api.example.com/w"), "Should include wget pattern");
});
