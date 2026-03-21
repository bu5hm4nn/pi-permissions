import test from "node:test";
import assert from "node:assert/strict";
import { preprocessHeredocs, stripHeredocBodies } from "../src/shell/parser/heredoc-preprocess.ts";

test("identifies and strips simple heredoc", () => {
	const input = `cat <<'EOF'
hello world
EOF`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	assert.equal(result.heredocCount, 1);
	assert.deepEqual(result.delimiters, ["EOF"]);
	// Should strip the entire heredoc construct: redirect + body + closing delimiter
	assert.ok(!result.preprocessed.includes("hello world"), "Should strip body content");
	assert.ok(!result.preprocessed.includes("EOF"), "Should strip closing delimiter");
	// Result should just be the command before the heredoc
	assert.equal(result.preprocessed.trim(), "cat");
});

test("strips heredoc redirect and body completely", () => {
	const input = `python3 - <<'PY'
import json
x = json.loads(data)
PY`;
	const stripped = stripHeredocBodies(input);
	// Should strip everything including the heredoc redirect (<<'PY')
	assert.ok(!stripped.includes("<<'PY'"), "Should strip heredoc redirect");
	assert.ok(!stripped.includes("json.loads"), "Should strip heredoc body");
	assert.ok(!stripped.includes("PY"), "Should strip closing delimiter");
	// Result should just be the command before the heredoc
	assert.equal(stripped.trim(), "python3 -");
});

test("handles multiple heredocs", () => {
	const input = `cat <<'EOF1'
first
EOF1
cat <<'EOF2'
second
EOF2`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	assert.equal(result.heredocCount, 2);
	assert.deepEqual(result.delimiters.includes("EOF1"), true);
	assert.deepEqual(result.delimiters.includes("EOF2"), true);
});

test("handles unquoted heredoc delimiter", () => {
	const input = `cat <<EOF
plain text
EOF`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	assert.equal(result.heredocCount, 1);
	assert.deepEqual(result.delimiters.includes("EOF"), true);
});

test("handles tab-stripping heredoc with <<- syntax", () => {
	const input = `cat <<-TAB
	indented content
	TAB`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	assert.equal(result.heredocCount, 1);
	assert.ok(result.delimiters.includes("TAB"));
});

test("handles double-quoted heredoc delimiter", () => {
	const input = `cat <<"DELIM"
content
DELIM`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	assert.equal(result.heredocCount, 1);
});

test("returns unchanged for commands without heredocs", () => {
	const input = "echo hello && cat /etc/passwd";
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, false);
	assert.equal(result.heredocCount, 0);
	assert.equal(result.preprocessed, input);
});

test("handles heredoc on same line as other commands", () => {
	const input = `echo "starting"; python3 - <<'PY'
import json
print(json.dumps({"x": 1}))
PY
echo "done"`;
	const stripped = stripHeredocBodies(input);
	assert.ok(stripped.includes("echo \"starting\""));
	assert.ok(stripped.includes("echo \"done\""));
	assert.ok(!stripped.includes("json.dumps"));
	assert.ok(!stripped.includes("<<'PY'"), "Should strip heredoc redirect");
});

test("handles heredoc with Python function calls that confuse parser", () => {
	const input = `python3 - <<'PY'
from pathlib import Path
cfg = json.loads(Path('config.json').read_text())
print(cfg.get('key'))
PY`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	// The parser would fail on json.loads(...) - check that it's stripped
	assert.ok(!result.preprocessed.includes("json.loads"));
	// Entire heredoc construct should be removed
	assert.ok(!result.preprocessed.includes("<<'PY'"), "Should strip heredoc redirect");
});

test("handles node heredoc with JavaScript code", () => {
	const input = `node --input-type=module <<'EOF'
import fs from 'node:fs';
const cfg = JSON.parse(fs.readFileSync('/home/node/.openclaw/openclaw.json', 'utf8'));
console.log(JSON.stringify(cfg, null, 2));
EOF`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	assert.ok(!result.preprocessed.includes("JSON.parse"));
	assert.ok(!result.preprocessed.includes("<<'EOF'"), "Should strip heredoc redirect");
});

test("handles heredoc with nested parentheses", () => {
	const input = `python3 - <<'PY'
def func(x):
    return (x + 1) * (x - 1)
print(func(5))
PY`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	assert.ok(!result.preprocessed.includes("func(x)"));
	assert.ok(!result.preprocessed.includes("<<'PY'"), "Should strip heredoc redirect");
});

test("handles complex python heredoc with function definitions and classes", () => {
	const input = `python3 - <<'PY'
from pathlib import Path
import json

class Config:
    def __init__(self, path):
        self.data = json.loads(Path(path).read_text())
    
    def get(self, key, default=None):
        return self.data.get(key, default)

cfg = Config('config.json')
print(cfg.get('key'))
PY`;
	const result = preprocessHeredocs(input);
	assert.equal(result.hasHeredocs, true);
	assert.equal(result.heredocCount, 1);
	// Should strip the entire heredoc construct
	assert.ok(!result.preprocessed.includes("<<'PY'"), "Should strip heredoc redirect");
	assert.ok(!result.preprocessed.includes("class Config"));
	assert.ok(!result.preprocessed.includes("def __init__"));
});