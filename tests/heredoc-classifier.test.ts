import test from "node:test";
import assert from "node:assert/strict";
import {
	detectHeredocLanguage,
	extractHeredocs,
	classifyHeredoc,
	analyzeHeredocs,
	getOverallHeredocRisk,
	formatHeredocAnalysis,
} from "../src/shell/analyzers/heredoc-classifier.ts";

// === Language Detection ===

test("detectHeredocLanguage detects Python", () => {
	assert.equal(detectHeredocLanguage("PY"), "python");
	assert.equal(detectHeredocLanguage("PYTHON"), "python");
	assert.equal(detectHeredocLanguage("py"), "python");
});

test("detectHeredocLanguage detects Bash", () => {
	assert.equal(detectHeredocLanguage("BASH"), "bash");
	assert.equal(detectHeredocLanguage("SH"), "bash");
	assert.equal(detectHeredocLanguage("SHELL"), "bash");
});

test("detectHeredocLanguage detects JavaScript", () => {
	assert.equal(detectHeredocLanguage("JS"), "javascript");
	assert.equal(detectHeredocLanguage("JAVASCRIPT"), "javascript");
});

test("detectHeredocLanguage detects Ruby", () => {
	assert.equal(detectHeredocLanguage("RB"), "ruby");
	assert.equal(detectHeredocLanguage("RUBY"), "ruby");
});

test("detectHeredocLanguage detects Perl", () => {
	assert.equal(detectHeredocLanguage("PL"), "perl");
	assert.equal(detectHeredocLanguage("PERL"), "perl");
});

test("detectHeredocLanguage defaults to bash for unknown", () => {
	assert.equal(detectHeredocLanguage("RANDOM_DELIMITER"), "bash");
	assert.equal(detectHeredocLanguage("EOF"), "bash");
});

// === Heredoc Extraction ===

test("extractHeredocs extracts single heredoc", () => {
	const cmd = `python3 - <<'PY'
print("hello")
PY`;
	const heredocs = extractHeredocs(cmd);
	assert.equal(heredocs.length, 1);
	assert.equal(heredocs[0].delimiter, "PY");
	assert.equal(heredocs[0].language, "python");
	assert.equal(heredocs[0].content, 'print("hello")');
});

test("extractHeredoc extracts heredoc without quotes", () => {
	const cmd = `bash <<EOF
echo hello
EOF`;
	const heredocs = extractHeredocs(cmd);
	assert.equal(heredocs.length, 1);
	assert.equal(heredocs[0].delimiter, "EOF");
	assert.equal(heredocs[0].language, "bash");
});

test("extractHeredoc extracts heredoc with tab stripping", () => {
	const cmd = `bash <<-TAB
\techo hello
TAB`;
	const heredocs = extractHeredocs(cmd);
	assert.equal(heredocs.length, 1);
	assert.equal(heredocs[0].delimiter, "TAB");
});

test("extractHeredocs handles multiple heredocs", () => {
	const cmd = `python3 <<'PY'
print("first")
PY
bash <<'SH'
echo "second"
SH`;
	const heredocs = extractHeredocs(cmd);
	assert.equal(heredocs.length, 2);
	assert.equal(heredocs[0].language, "python");
	assert.equal(heredocs[1].language, "bash");
});

// === Python Classification ===

test("classifyHeredoc classifies Python print-only as readonly", () => {
	const content = `print("hello world")
x = 1 + 1
print(x)`;
	const result = classifyHeredoc(content, "python");
	assert.equal(result.classification, "readonly");
	// print() is detected as readonly pattern, so confidence is high
	assert.equal(result.confidence, "high");
});

test("classifyHeredoc classifies Python file read as readonly", () => {
	const content = `with open('input.txt', 'r') as f:
    data = f.read()
print(data)`;
	const result = classifyHeredoc(content, "python");
	assert.equal(result.classification, "readonly");
	assert.equal(result.confidence, "high");
});

test("classifyHeredoc classifies Python requests.get as readonly", () => {
	const content = `import requests
resp = requests.get('https://example.com')
print(resp.text)`;
	const result = classifyHeredoc(content, "python");
	assert.equal(result.classification, "readonly");
	assert.equal(result.confidence, "high");
});

test("classifyHeredoc classifies Python file write as modify", () => {
	const content = `with open('output.txt', 'w') as f:
    f.write("hello")`;
	const result = classifyHeredoc(content, "python");
	assert.equal(result.classification, "modify");
	assert.equal(result.confidence, "high");
	assert.ok(result.writeOperations.length > 0);
});

test("classifyHeredoc classifies Python os.remove as modify", () => {
	const content = `import os
os.remove('temp.txt')`;
	const result = classifyHeredoc(content, "python");
	assert.equal(result.classification, "modify");
	assert.equal(result.confidence, "high");
});

test("classifyHeredoc classifies Python shutil.rmtree as modify", () => {
	const content = `import shutil
shutil.rmtree('./build')`;
	const result = classifyHeredoc(content, "python");
	assert.equal(result.classification, "modify");
});

test("classifyHeredoc classifies Python requests.post as modify", () => {
	const content = `import requests
requests.post('https://api.example.com', json={'key': 'value'})`;
	const result = classifyHeredoc(content, "python");
	assert.equal(result.classification, "modify");
});

// === Bash Classification ===

test("classifyHeredoc classifies Bash echo-only as readonly", () => {
	const content = `echo "hello"
echo "world"`;
	const result = classifyHeredoc(content, "bash");
	assert.equal(result.classification, "readonly");
});

test("classifyHeredoc classifies Bash cat as readonly", () => {
	const content = `cat /etc/passwd
head -n 10 file.txt`;
	const result = classifyHeredoc(content, "bash");
	assert.equal(result.classification, "readonly");
});

test("classifyHeredoc classifies Bash redirect write as modify", () => {
	const content = `echo "hello" > output.txt`;
	const result = classifyHeredoc(content, "bash");
	assert.equal(result.classification, "modify");
	assert.ok(result.writeOperations.some((op) => op.includes(">")));
});

test("classifyHeredoc classifies Bash >> as modify", () => {
	const content = `echo "line" >> log.txt`;
	const result = classifyHeredoc(content, "bash");
	assert.equal(result.classification, "modify");
});

test("classifyHeredoc classifies Bash rm as modify", () => {
	const content = `rm -rf ./build`;
	const result = classifyHeredoc(content, "bash");
	assert.equal(result.classification, "modify");
});

test("classifyHeredoc classifies Bash sed -i as modify", () => {
	const content = `sed -i 's/old/new/' file.txt`;
	const result = classifyHeredoc(content, "bash");
	assert.equal(result.classification, "modify");
});

test("classifyHeredoc classifies Bash curl -O as readonly", () => {
	const content = `curl -O https://example.com/file.zip`;
	const result = classifyHeredoc(content, "bash");
	// curl -O downloads but doesn't modify files in place (writes to new file)
	// This could be argued as modify, but typically curl fetch is considered readonly
	// for security analysis purposes
	assert.equal(result.classification, "readonly");
});

// === JavaScript Classification ===

test("classifyHeredoc classifies JS fs.readFile as readonly", () => {
	const content = `const fs = require('fs');
const data = fs.readFileSync('input.txt', 'utf8');
console.log(data);`;
	const result = classifyHeredoc(content, "javascript");
	assert.equal(result.classification, "readonly");
});

test("classifyHeredoc classifies JS fs.writeFile as modify", () => {
	const content = `const fs = require('fs');
fs.writeFileSync('output.txt', 'hello');`;
	const result = classifyHeredoc(content, "javascript");
	assert.equal(result.classification, "modify");
});

test("classifyHeredoc classifies JS fetch GET as readonly", () => {
	const content = `fetch('https://api.example.com/data')
  .then(r => r.json())
  .then(console.log);`;
	const result = classifyHeredoc(content, "javascript");
	assert.equal(result.classification, "readonly");
});

test("classifyHeredoc classifies JS fetch POST as modify", () => {
	const content = `fetch('https://api.example.com/data', {
  method: 'POST',
  body: JSON.stringify({key: 'value'})
});`;
	const result = classifyHeredoc(content, "javascript");
	assert.equal(result.classification, "modify");
});

// === Ruby Classification ===

test("classifyHeredoc classifies Ruby File.read as readonly", () => {
	const content = `data = File.read('input.txt')
puts data`;
	const result = classifyHeredoc(content, "ruby");
	assert.equal(result.classification, "readonly");
});

test("classifyHeredoc classifies Ruby File.write as modify", () => {
	const content = `File.write('output.txt', 'hello')`;
	const result = classifyHeredoc(content, "ruby");
	assert.equal(result.classification, "modify");
});

test("classifyHeredoc classifies Ruby FileUtils.rm as modify", () => {
	const content = `require 'fileutils'
FileUtils.rm('temp.txt')`;
	const result = classifyHeredoc(content, "ruby");
	assert.equal(result.classification, "modify");
});

// === Perl Classification ===

test("classifyHeredoc classifies Perl print as readonly", () => {
	const content = `print "hello world\n";`;
	const result = classifyHeredoc(content, "perl");
	assert.equal(result.classification, "readonly");
});

test("classifyHeredoc classifies Perl open for write as modify", () => {
	const content = `open(my $fh, '>', 'output.txt') or die;
print $fh "hello";`;
	const result = classifyHeredoc(content, "perl");
	assert.equal(result.classification, "modify");
});

test("classifyHeredoc classifies Perl unlink as modify", () => {
	const content = `unlink 'temp.txt';`;
	const result = classifyHeredoc(content, "perl");
	assert.equal(result.classification, "modify");
});

// === Edge Cases ===

test("classifyHeredoc returns unknown for ambiguous content", () => {
	const content = `# Some code that doesn't match patterns
do_something()`;
	const result = classifyHeredoc(content, "python");
	assert.equal(result.classification, "unknown");
	assert.equal(result.confidence, "low");
});

test("classifyHeredoc handles empty content", () => {
	const result = classifyHeredoc("", "bash");
	assert.equal(result.classification, "unknown");
});

// === Full Analysis ===

test("analyzeHeredocs returns empty array for no heredocs", () => {
	const result = analyzeHeredocs("echo hello");
	assert.equal(result.length, 0);
});

test("analyzeHeredocs classifies Python web scraping script as readonly", () => {
	const cmd = `python3 - <<'PY'
import requests
from bs4 import BeautifulSoup
resp = requests.get('https://example.com')
soup = BeautifulSoup(resp.text, 'html.parser')
print(soup.find('title').text)
PY`;
	const result = analyzeHeredocs(cmd);
	assert.equal(result.length, 1);
	assert.equal(result[0].classification, "readonly");
	assert.equal(result[0].language, "python");
});

test("analyzeHeredocs classifies Python file modification script as modify", () => {
	const cmd = `python3 - <<'PY'
import os
os.remove('old.txt')
with open('new.txt', 'w') as f:
    f.write('content')
PY`;
	const result = analyzeHeredocs(cmd);
	assert.equal(result.length, 1);
	assert.equal(result[0].classification, "modify");
	assert.ok(result[0].writeOperations.length >= 2);
});

// === Risk Aggregation ===

test("getOverallHeredocRisk returns modify if any heredoc modifies", () => {
	const analyses = [
		{ classification: "readonly" as const, language: "python" as const, confidence: "high" as const, reasoning: "", writeOperations: [], heredocContent: "" },
		{ classification: "modify" as const, language: "bash" as const, confidence: "high" as const, reasoning: "", writeOperations: ["rm"], heredocContent: "" },
	];
	assert.equal(getOverallHeredocRisk(analyses), "modify");
});

test("getOverallHeredocRisk returns unknown if any heredoc is unknown", () => {
	const analyses = [
		{ classification: "readonly" as const, language: "python" as const, confidence: "high" as const, reasoning: "", writeOperations: [], heredocContent: "" },
		{ classification: "unknown" as const, language: "bash" as const, confidence: "low" as const, reasoning: "", writeOperations: [], heredocContent: "" },
	];
	assert.equal(getOverallHeredocRisk(analyses), "unknown");
});

test("getOverallHerdockRisk returns readonly if all readonly", () => {
	const analyses = [
		{ classification: "readonly" as const, language: "python" as const, confidence: "high" as const, reasoning: "", writeOperations: [], heredocContent: "" },
		{ classification: "readonly" as const, language: "bash" as const, confidence: "medium" as const, reasoning: "", writeOperations: [], heredocContent: "" },
	];
	assert.equal(getOverallHeredocRisk(analyses), "readonly");
});

// === Formatting ===

test("formatHerdockAnalysis returns empty string for no heredocs", () => {
	assert.equal(formatHeredocAnalysis([]), "");
});

test("formatHerdockAnalysis formats readonly heredoc", () => {
	const analyses = [{
		language: "python" as const,
		classification: "readonly" as const,
		confidence: "high" as const,
		reasoning: "Only reads and prints",
		writeOperations: [],
		heredocContent: "",
	}];
	const result = formatHeredocAnalysis(analyses);
	assert.ok(result.includes("python: readonly"));
	assert.ok(result.includes("✓"));
});

test("formatHeredocAnalysis formats modify heredoc with write ops", () => {
	const analyses = [{
		language: "python" as const,
		classification: "modify" as const,
		confidence: "high" as const,
		reasoning: "Writes files",
		writeOperations: ["open(..., 'w')", "os.remove"],
		heredocContent: "",
	}];
	const result = formatHeredocAnalysis(analyses);
	assert.ok(result.includes("python: modify"));
	assert.ok(result.includes("⚠"));
	assert.ok(result.includes("Write ops:"));
});