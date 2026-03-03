import test from "node:test";
import assert from "node:assert/strict";
import { getFallbackPattern } from "../src/shell/analyzers/command-patterns.ts";

test("getFallbackPattern computes correct fallbacks", () => {
	assert.equal(getFallbackPattern("curl POST https://api.example.com/foo"), "curl POST *");
	assert.equal(getFallbackPattern("wget DELETE https://api.example.com/foo"), "wget DELETE *");
	assert.equal(getFallbackPattern("curl GET *"), null);
	assert.equal(getFallbackPattern("docker run *"), null);
	assert.equal(getFallbackPattern("echo *"), null);
});
