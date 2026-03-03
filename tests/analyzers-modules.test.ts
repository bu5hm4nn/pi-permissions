import test from "node:test";
import assert from "node:assert/strict";
import { isDirectSshFamilyCommand as analyzerDirectSsh } from "../src/shell/analyzers/direct-ssh.ts";
import { analyzeCommandPatterns as analyzerCommandPatterns } from "../src/shell/analyzers/command-patterns.ts";
import { extractDockerShellPatterns } from "../src/shell/analyzers/docker-patterns.ts";
import { extractCurlMethodPatterns } from "../src/shell/analyzers/curl-patterns.ts";
import { extractWgetMethodPatterns } from "../src/shell/analyzers/wget-patterns.ts";
import { isDirectSshFamilyCommand as adapterDirectSsh } from "../src/ssh/matcher.ts";
import { analyzeCommandPatterns as adapterCommandPatterns } from "../src/policy/command-patterns.ts";

test("ssh matcher adapter preserves direct-ssh analyzer behavior", () => {
	const commands = [
		"echo ok",
		"ssh user@host",
		"sudo -- ssh user@host",
		"echo 'unterminated",
		"cat <(ssh user@host)",
	];
	for (const command of commands) {
		assert.equal(adapterDirectSsh(command), analyzerDirectSsh(command));
	}
});

test("policy command-patterns adapter preserves analyzer behavior", () => {
	const commands = [
		"echo hi && cat /etc/hosts",
		"docker ps --format '{{.Names}}'",
		"docker run --rm alpine sh -lc 'echo hi && id'",
		"curl -d 'a=1' https://api.example.com/a --next curl -I https://api.example.com/b",
		"curl -X DELETE https://api.example.com/v1/items/1 && wget --method=DELETE https://api.example.com/v1/items/2",
		"$RUNNER foo",
	];
	for (const command of commands) {
		assert.deepEqual(adapterCommandPatterns(command), analyzerCommandPatterns(command));
	}
});

test("curl analyzer module extracts transfer methods", () => {
	const analysis = extractCurlMethodPatterns(["-d", "a=1", "https://api.example.com/a", "--next", "-I", "https://api.example.com/b"]);
	assert.equal(analysis.complete, true);
	assert.deepEqual(new Set(analysis.patterns), new Set(["curl POST https://api.example.com/a", "curl HEAD *"]));
});

test("curl analyzer module keeps GET/HEAD broad but URL-scopes mutating methods", () => {
	const get = extractCurlMethodPatterns(["https://api.example.com/health"]);
	assert.equal(get.complete, true);
	assert.deepEqual(get.patterns, ["curl GET *"]);

	const head = extractCurlMethodPatterns(["-I", "https://api.example.com/items"]);
	assert.equal(head.complete, true);
	assert.deepEqual(head.patterns, ["curl HEAD *"]);

	const post = extractCurlMethodPatterns(["-X", "POST", "https://api.example.com/items"]);
	assert.equal(post.complete, true);
	assert.deepEqual(post.patterns, ["curl POST https://api.example.com/items"]);

	const put = extractCurlMethodPatterns(["-X", "PUT", "https://api.example.com/v1/items/2"]);
	assert.equal(put.complete, true);
	assert.deepEqual(put.patterns, ["curl PUT https://api.example.com/v1/items/2"]);

	const patch = extractCurlMethodPatterns(["-X", "PATCH", "https://api.example.com/v1/items/2"]);
	assert.equal(patch.complete, true);
	assert.deepEqual(patch.patterns, ["curl PATCH https://api.example.com/v1/items/2"]);

	const del = extractCurlMethodPatterns(["-X", "DELETE", "https://api.example.com/v1/items/1"]);
	assert.equal(del.complete, true);
	assert.deepEqual(del.patterns, ["curl DELETE https://api.example.com/v1/items/1"]);

	const canonicalDelete = extractCurlMethodPatterns(["-X", "DELETE", "HTTPS://API.EXAMPLE.COM:443/v1/items/1?force=true#frag"]);
	assert.equal(canonicalDelete.complete, true);
	assert.deepEqual(canonicalDelete.patterns, ["curl DELETE https://api.example.com/v1/items/1"]);
});

test("curl analyzer module NEVER exposes credentials in URL-scoped patterns (security)", () => {
	// Security: URLs with embedded credentials must NOT appear in patterns
	// canonicalizeTransferUrl strips credentials (only uses protocol/hostname/port/pathname)
	const credUrl = extractCurlMethodPatterns(["-X", "POST", "https://user:secret-token@api.example.com/items"]);
	assert.equal(credUrl.complete, true);
	assert.equal(credUrl.patterns[0].includes("user:secret-token"), false,
		"Pattern MUST NOT contain credentials from raw URL");
	assert.equal(credUrl.patterns[0].includes("secret"), false,
		"Pattern MUST NOT contain any part of the secret");
	assert.deepEqual(credUrl.patterns, ["curl POST https://api.example.com/items"],
		"Canonicalized URL should have credentials stripped");
});

test("curl analyzer module uses wildcard for malformed URLs that fail canonicalization (security)", () => {
	// Security: When URL canonicalization fails, must use "*" instead of raw URL
	const noProtocol = extractCurlMethodPatterns(["-X", "PUT", "api.example.com/path"]);
	assert.equal(noProtocol.complete, true);
	assert.deepEqual(noProtocol.patterns, ["curl PUT *"],
		"URL without protocol must NOT appear in pattern; use wildcard instead");

	const emptyHost = extractCurlMethodPatterns(["-X", "DELETE", "https://"]);
	assert.equal(emptyHost.complete, true);
	assert.deepEqual(emptyHost.patterns, ["curl DELETE *"],
		"Malformed URL with empty host must NOT appear in pattern; use wildcard instead");

	const invalidSyntax = extractCurlMethodPatterns(["-X", "POST", "://broken"]);
	assert.equal(invalidSyntax.complete, true);
	assert.deepEqual(invalidSyntax.patterns, ["curl POST *"],
		"Invalid URL syntax must NOT appear in pattern; use wildcard instead");
});

test("docker analyzer module extracts nested shell command patterns", () => {
	const nested = extractDockerShellPatterns(
		["--rm", "alpine", "sh", "-lc", "echo hi && id"],
		"run",
		0,
		(payload) => analyzerCommandPatterns(payload),
	);
	assert.equal(nested.complete, true);
	assert.deepEqual(new Set(nested.patterns), new Set(["echo *", "id *"]));
});

test("wget analyzer module extracts transfer method", () => {
	const analysis = extractWgetMethodPatterns(["--post-data=a=1", "https://api.example.com/a"]);
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["wget POST https://api.example.com/a"]);
});

test("wget analyzer module treats malformed --method parsing as incomplete", () => {
	const emptyMethodValue = extractWgetMethodPatterns(["--method=", "https://api.example.com/a"]);
	assert.equal(emptyMethodValue.complete, false);
	assert.deepEqual(emptyMethodValue.patterns, []);

	const optionTokenAsMethod = extractWgetMethodPatterns(["--method", "--post-data=x", "https://api.example.com/a"]);
	assert.equal(optionTokenAsMethod.complete, false);
	assert.deepEqual(optionTokenAsMethod.patterns, []);
});

test("wget analyzer module NEVER exposes credentials in URL-scoped patterns (security)", () => {
	// Security: URLs with embedded credentials must NOT appear in patterns
	// canonicalizeTransferUrl strips credentials (only uses protocol/hostname/port/pathname)
	// but this test ensures the security property holds regardless of implementation details
	const credUrl = extractWgetMethodPatterns(["--method=POST", "https://user:secret-token@api.example.com/items"]);
	assert.equal(credUrl.complete, true);
	// Credentials are stripped during canonicalization - raw URL must NEVER appear
	assert.equal(credUrl.patterns[0].includes("user:secret-token"), false, 
		"Pattern MUST NOT contain credentials from raw URL");
	assert.equal(credUrl.patterns[0].includes("secret"), false,
		"Pattern MUST NOT contain any part of the secret");
	assert.deepEqual(credUrl.patterns, ["wget POST https://api.example.com/items"],
		"Canonicalized URL should have credentials stripped");
});

test("wget analyzer module uses wildcard for malformed URLs that fail canonicalization (security)", () => {
	// Security: When URL canonicalization fails, must use "*" instead of raw URL
	// The raw URL may be malformed but could still leak sensitive data in logs/patterns
	
	// URL without protocol - fails URL parsing
	const noProtocol = extractWgetMethodPatterns(["--method=PUT", "api.example.com/path"]);
	assert.equal(noProtocol.complete, true);
	assert.deepEqual(noProtocol.patterns, ["wget PUT *"],
		"URL without protocol must NOT appear in pattern; use wildcard instead");
	
	// Empty href after protocol - fails URL parsing  
	const emptyHost = extractWgetMethodPatterns(["--method=DELETE", "https://"]);
	assert.equal(emptyHost.complete, true);
	assert.deepEqual(emptyHost.patterns, ["wget DELETE *"],
		"Malformed URL with empty host must NOT appear in pattern; use wildcard instead");
	
	// Completely invalid URL syntax
	const invalidSyntax = extractWgetMethodPatterns(["--method=POST", "://broken"]);
	assert.equal(invalidSyntax.complete, true);
	assert.deepEqual(invalidSyntax.patterns, ["wget POST *"],
		"Invalid URL syntax must NOT appear in pattern; use wildcard instead");
});

test("wget analyzer module canonicalizes valid URLs correctly (no regression)", () => {
	// Regression test: ensure valid URLs are still canonicalized properly
	const validPost = extractWgetMethodPatterns(["--method=POST", "HTTPS://API.EXAMPLE.COM:443/v1/items?force=true"]);
	assert.equal(validPost.complete, true);
	assert.deepEqual(validPost.patterns, ["wget POST https://api.example.com/v1/items"],
		"Valid URL should be canonicalized (lowercase, default port stripped, query/hash removed)");
	
	const validPut = extractWgetMethodPatterns(["--method=PUT", "https://api.example.com:8443/special-port"]);
	assert.equal(validPut.complete, true);
	assert.deepEqual(validPut.patterns, ["wget PUT https://api.example.com:8443/special-port"],
		"Non-default port should be preserved");
});
