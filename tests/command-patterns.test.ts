import test from "node:test";
import assert from "node:assert/strict";
import { analyzeCommandPatterns, formatAllowPatternSummary } from "../src/policy/command-patterns.ts";

test("extracts per-command patterns from chained command", () => {
	const cmd = 'echo "=== Caddy Caddyfile ===" && cat /opt/caddy/Caddyfile && echo -e "\\n=== /etc/hosts ==="';
	const analysis = analyzeCommandPatterns(cmd);
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns.sort(), ["cat *", "echo *"]);
});

test("simple docker command with version flag is complete", () => {
	// docker --version is a complete, safe command with specific pattern
	const analysis = analyzeCommandPatterns("docker --version");
	assert.equal(analysis.complete, true, "docker --version should be analyzed as complete");
	assert.deepEqual(analysis.patterns, ["docker --version"]);
});

test("docker compound command with version and subcommand is complete", () => {
	// docker --version && docker compose version is a simple, fully parseable compound command
	// Both commands are informational with specific patterns
	const analysis = analyzeCommandPatterns("docker --version && docker compose version");
	assert.equal(analysis.complete, true, "docker --version && docker compose version should be analyzed as complete");
	assert.deepEqual(analysis.patterns.sort(), ["docker --version", "docker compose version"]);
});

test("matches docker command by subcommand", () => {
	const analysis = analyzeCommandPatterns("docker ps --format '{{.Names}}'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["docker ps *"]);
});

test("extracts inner commands for docker run shell payload", () => {
	const analysis = analyzeCommandPatterns(
		"docker run --rm fmartinou/whats-up-docker:latest sh -lc 'find / -maxdepth 3 -type d -name \"*whats*\" -o -name \"*wud*\" && echo done'",
	);
	assert.equal(analysis.complete, true);
	assert.deepEqual(new Set(analysis.patterns), new Set(["docker run *", "docker(run): find *", "docker(run): echo *"]));
});

test("extracts inner commands for docker exec shell payload", () => {
	const analysis = analyzeCommandPatterns("docker exec ntfy sh -lc 'echo users && ntfy user list'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(new Set(analysis.patterns), new Set(["docker exec *", "docker(exec): echo *", "docker(exec): ntfy *"]));
});

test("extracts inner commands for docker exec with -- separator", () => {
	const analysis = analyzeCommandPatterns("docker exec -- ntfy sh -lc 'echo users && ntfy user list'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(new Set(analysis.patterns), new Set(["docker exec *", "docker(exec): echo *", "docker(exec): ntfy *"]));
});

test("extracts inner commands for docker run with -- separator", () => {
	const analysis = analyzeCommandPatterns("docker run -- alpine sh -lc 'echo hi && id'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(new Set(analysis.patterns), new Set(["docker run *", "docker(run): echo *", "docker(run): id *"]));
});

test("does not parse fake shell fragments passed as regular docker command arguments", () => {
	const analysis = analyzeCommandPatterns("docker run --rm alpine echo sh -lc 'rm -rf /'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(new Set(analysis.patterns), new Set(["docker run *", "docker(run): echo *"]));
});

test("docker subcommand is found after flags", () => {
	// docker --context prod ps -- now correctly identifies 'ps' as subcommand after skipping '--context prod'
	const analysis = analyzeCommandPatterns("docker --context prod ps --format '{{.Names}}'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["docker ps *"]);
});

test("docker boolean flags do not skip subcommand", () => {
	// docker -D ps - '-D' is a boolean flag, 'ps' should still be found as subcommand
	const analysis = analyzeCommandPatterns("docker -D ps -a");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["docker ps *"]);
});

test("docker compose version gets specific pattern, not wildcard", () => {
	// docker compose version is informational, should use specific pattern
	const analysis = analyzeCommandPatterns("docker compose version");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["docker compose version"]);
});

test("git info commands use wildcard, not specific pattern", () => {
	// git is not docker - info commands should still use wildcard
	const analysis = analyzeCommandPatterns("git version");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["git version *"]);
});

test("kubectl info commands use wildcard, not specific pattern", () => {
	// kubectl is not docker - info commands should still use wildcard
	const analysis = analyzeCommandPatterns("kubectl version --client");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["kubectl version *"]);
});

test("distinguishes curl methods", () => {
	const getDefault = analyzeCommandPatterns("curl -s https://api.example.com/health");
	assert.equal(getDefault.complete, true);
	assert.deepEqual(getDefault.patterns, ["curl GET *"]);

	const postData = analyzeCommandPatterns("curl -s -d '{\"x\":1}' https://api.example.com/items");
	assert.equal(postData.complete, true);
	assert.deepEqual(postData.patterns, ["curl POST https://api.example.com/items"]);

	const postExplicit = analyzeCommandPatterns("curl -X POST https://api.example.com/items");
	assert.equal(postExplicit.complete, true);
	assert.deepEqual(postExplicit.patterns, ["curl POST https://api.example.com/items"]);

	const put = analyzeCommandPatterns("curl -X PUT https://api.example.com/items/1");
	assert.equal(put.complete, true);
	assert.deepEqual(put.patterns, ["curl PUT https://api.example.com/items/1"]);

	const patch = analyzeCommandPatterns("curl -X PATCH https://api.example.com/items/1");
	assert.equal(patch.complete, true);
	assert.deepEqual(patch.patterns, ["curl PATCH https://api.example.com/items/1"]);

	const del = analyzeCommandPatterns("curl -X DELETE https://api.example.com/items/1");
	assert.equal(del.complete, true);
	assert.deepEqual(del.patterns, ["curl DELETE https://api.example.com/items/1"]);

	const canonicalDelete = analyzeCommandPatterns("curl -X DELETE HTTPS://API.EXAMPLE.COM:443/items/1?force=true#frag");
	assert.equal(canonicalDelete.complete, true);
	assert.deepEqual(canonicalDelete.patterns, ["curl DELETE https://api.example.com/items/1"]);
});

test("keeps curl GET broad but scopes mutating methods to URL", () => {
	const get = analyzeCommandPatterns("curl https://api.example.com/health");
	assert.equal(get.complete, true);
	assert.deepEqual(get.patterns, ["curl GET *"]);

	const post = analyzeCommandPatterns("curl -X POST https://api.example.com/items");
	assert.equal(post.complete, true);
	assert.deepEqual(post.patterns, ["curl POST https://api.example.com/items"]);

	const del = analyzeCommandPatterns("curl -X DELETE https://api.example.com/v1/items/1");
	assert.equal(del.complete, true);
	assert.deepEqual(del.patterns, ["curl DELETE https://api.example.com/v1/items/1"]);

	const put = analyzeCommandPatterns("curl -X PUT https://api.example.com/v1/items/2");
	assert.equal(put.complete, true);
	assert.deepEqual(put.patterns, ["curl PUT https://api.example.com/v1/items/2"]);

	const patch = analyzeCommandPatterns("curl -X PATCH https://api.example.com/v1/items/2");
	assert.equal(patch.complete, true);
	assert.deepEqual(patch.patterns, ["curl PATCH https://api.example.com/v1/items/2"]);
});

test("handles additional curl method-affecting flags", () => {
	const formattedPost = analyzeCommandPatterns(
		"curl -s -o /dev/null -w '%{http_code}\\n' -H 'Authorization: Bearer tok' -H 'Title: channel check' -H 'Tags: test,package' -d 'manual test' https://n.example.com/topic",
	);
	assert.equal(formattedPost.complete, true);
	assert.deepEqual(formattedPost.patterns, ["curl POST https://n.example.com/topic"]);

	const postJson = analyzeCommandPatterns("curl --json '{\"x\":1}' https://api.example.com/items");
	assert.equal(postJson.complete, true);
	assert.deepEqual(postJson.patterns, ["curl POST https://api.example.com/items"]);

	const postFormString = analyzeCommandPatterns("curl --form-string 'a=b' https://api.example.com/items");
	assert.equal(postFormString.complete, true);
	assert.deepEqual(postFormString.patterns, ["curl POST https://api.example.com/items"]);

	const forceGet = analyzeCommandPatterns("curl -G -d 'a=b' https://api.example.com/items");
	assert.equal(forceGet.complete, true);
	assert.deepEqual(forceGet.patterns, ["curl GET *"]);

	const head = analyzeCommandPatterns("curl -I https://api.example.com/items");
	assert.equal(head.complete, true);
	assert.deepEqual(head.patterns, ["curl HEAD *"]);

	const putUpload = analyzeCommandPatterns("curl -T file.txt https://api.example.com/upload");
	assert.equal(putUpload.complete, true);
	assert.deepEqual(putUpload.patterns, ["curl PUT https://api.example.com/upload"]);
});

test("handles curl --next as separate transfers", () => {
	const analysis = analyzeCommandPatterns("curl -d a=1 https://api.example.com/a --next curl -I https://api.example.com/b");
	assert.equal(analysis.complete, true);
	assert.deepEqual(new Set(analysis.patterns), new Set(["curl POST https://api.example.com/a", "curl HEAD *"]));
});

test("does not fallback to broad curl pattern when method parsing is incomplete", () => {
	const analysis = analyzeCommandPatterns("curl --request");
	assert.equal(analysis.complete, false);
	assert.deepEqual(analysis.patterns, []);
});

test("distinguishes wget methods", () => {
	const getDefault = analyzeCommandPatterns("wget -qO- https://api.example.com/health");
	assert.equal(getDefault.complete, true);
	assert.deepEqual(getDefault.patterns, ["wget GET *"]);

	const postData = analyzeCommandPatterns("wget --post-data='x=1' https://api.example.com/items");
	assert.equal(postData.complete, true);
	assert.deepEqual(postData.patterns, ["wget POST https://api.example.com/items"]);

	const postMethod = analyzeCommandPatterns("wget --method=POST --body-data='x=1' https://api.example.com/items");
	assert.equal(postMethod.complete, true);
	assert.deepEqual(postMethod.patterns, ["wget POST https://api.example.com/items"]);

	const deleteMethod = analyzeCommandPatterns("wget --method=DELETE https://api.example.com/items/1");
	assert.equal(deleteMethod.complete, true);
	assert.deepEqual(deleteMethod.patterns, ["wget DELETE https://api.example.com/items/1"]);
});

test("does not fallback to broad wget pattern when method parsing is incomplete", () => {
	const missingMethodValue = analyzeCommandPatterns("wget --method");
	assert.equal(missingMethodValue.complete, false);
	assert.deepEqual(missingMethodValue.patterns, []);

	const emptyMethodValue = analyzeCommandPatterns("wget --method= https://api.example.com/items");
	assert.equal(emptyMethodValue.complete, false);
	assert.deepEqual(emptyMethodValue.patterns, []);

	const optionTokenAsMethod = analyzeCommandPatterns("wget --method --post-data=x https://api.example.com/items");
	assert.equal(optionTokenAsMethod.complete, false);
	assert.deepEqual(optionTokenAsMethod.patterns, []);
});

test("keeps curl+wget method parity in mixed command chains", () => {
	const analysis = analyzeCommandPatterns(
		"curl -X DELETE https://api.example.com/v1/items/1 && wget --method=DELETE https://api.example.com/v1/items/2",
	);
	assert.equal(analysis.complete, true);
	assert.deepEqual(new Set(analysis.patterns), new Set(["curl DELETE https://api.example.com/v1/items/1", "wget DELETE https://api.example.com/v1/items/2"]));
});

test("formats wget summaries with user-facing method examples", () => {
	const postSummary = formatAllowPatternSummary(["wget POST *"]);
	assert.equal(postSummary, '"wget POST *" (e.g., wget --post-data=... https://api.example.com/...)');

	const deleteSummary = formatAllowPatternSummary(["wget DELETE *"]);
	assert.equal(deleteSummary, '"wget DELETE *" (e.g., wget --method=DELETE https://api.example.com/...)');

	const urlScopedSummary = formatAllowPatternSummary(["wget POST https://api.example.com/v1/*"]);
	assert.equal(urlScopedSummary, '"wget POST https://api.example.com/v1/*" (e.g., wget --post-data=... https://api.example.com/v1/...)');
});

test("formats curl summaries with user-facing method examples", () => {
	const postSummary = formatAllowPatternSummary(["curl POST *"]);
	assert.equal(postSummary, '"curl POST *" (e.g., curl -X POST https://api.example.com/...)');

	const deleteSummary = formatAllowPatternSummary(["curl DELETE *"]);
	assert.equal(deleteSummary, '"curl DELETE *" (e.g., curl -X DELETE https://api.example.com/...)');

	const urlScopedSummary = formatAllowPatternSummary(["curl POST https://api.example.com/v1/*"]);
	assert.equal(urlScopedSummary, '"curl POST https://api.example.com/v1/*" (e.g., curl -X POST https://api.example.com/v1/...)');
});

test("marks analysis incomplete when command is dynamic", () => {
	const analysis = analyzeCommandPatterns("$RUNNER foo");
	assert.equal(analysis.complete, false);
	assert.deepEqual(analysis.patterns, []);
});

// === HEREDOC TESTS ===
// Heredoc preprocessing strips the body content before parsing, allowing
// the parser to extract the outer command pattern. The analysis is marked
// incomplete because the heredoc marker itself (`<<'PY'`) is technically
// incomplete without a body, but we still get useful patterns.

test("handles python heredoc with json.loads that would confuse parser", () => {
	// This is the exact pattern from the analysis log that was failing
	// Previously would fail with "Unexpected 'OPEN_PAREN'" parsing Python as shell
	const cmd = `python3 - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path('config.json').read_text())
print(cfg.get('key'))
PY`;
	const analysis = analyzeCommandPatterns(cmd);
	// After stripping heredocs, the command is parseable
	assert.equal(analysis.complete, true, "Heredoc commands are complete after stripping");
	assert.deepEqual(analysis.patterns, ["python3 *"]);
});

test("handles python heredoc in chained command with echo", () => {
	const cmd = `echo '--- config ---' && python3 - <<'PY'
import json
cfg = json.loads(data)
print(json.dumps(cfg))
PY`;
	const analysis = analyzeCommandPatterns(cmd);
	assert.equal(analysis.complete, true, "Heredoc commands are complete after stripping");
	assert.deepEqual(analysis.patterns.sort(), ["echo *", "python3 *"]);
});

test("handles node heredoc with JavaScript code", () => {
	const cmd = `node --input-type=module <<'EOF'
import fs from 'node:fs';
const cfg = JSON.parse(fs.readFileSync('/home/node/config.json', 'utf8'));
console.log(JSON.stringify(cfg, null, 2));
EOF`;
	const analysis = analyzeCommandPatterns(cmd);
	assert.equal(analysis.complete, true, "Heredoc commands are complete after stripping");
	assert.deepEqual(analysis.patterns, ["node *"]);
});

test("handles multiple heredocs in sequence", () => {
	const cmd = `set -euo pipefail
python3 - <<'PY'
from pathlib import Path
print(Path('file.txt').read_text())
PY

python3 - <<'PY'
import json
cfg = json.loads('{}')
print(cfg)
PY`;
	const analysis = analyzeCommandPatterns(cmd);
	// After stripping heredocs, the command is parseable
	assert.equal(analysis.complete, true, "Heredoc commands can be complete after stripping");
	// set is a builtin (no pattern), python3 should be extracted twice but deduplicated
	assert.ok(analysis.patterns.includes("python3 *"));
});

test("handles heredoc in docker compose exec command", () => {
	// This pattern appeared in the analysis log
	const cmd = `docker compose exec -T openclaw-gateway node --input-type=module <<'EOF'
import fs from 'node:fs';
const cfg = JSON.parse(fs.readFileSync('/home/node/config.json', 'utf8'));
console.log(JSON.stringify(cfg, null, 2));
EOF`;
	const analysis = analyzeCommandPatterns(cmd);
	// After stripping heredoc, the command is parseable and complete
	assert.equal(analysis.complete, true, "Heredoc commands can now be complete after stripping");
	assert.deepEqual(analysis.patterns, ["docker compose *"]);
});

test("handles curl followed by python heredoc", () => {
	const cmd = `sample=/tmp/sample.wav
curl -fsSL -o /tmp/sample.wav https://example.com/audio.wav
python3 - <<'PY'
from pathlib import Path
audio = Path('/tmp/sample.wav').read_bytes()
print(len(audio))
PY`;
	const analysis = analyzeCommandPatterns(cmd);
	// Analysis may be incomplete due to variable assignment, but patterns are extracted
	assert.equal(analysis.complete, false, "Heredoc commands may be incomplete due to variable assignments");
	assert.ok(analysis.patterns.includes("curl GET *"), "Should extract curl pattern");
	assert.ok(analysis.patterns.includes("python3 *"), "Should extract python3 pattern");
});
