/**
 * Heredoc classifier - determines if heredoc scripts are readonly vs modify.
 * Uses fast pattern matching first, can fall back to LLM classification.
 */

export type HeredocLanguage =
	| "python"
	| "bash"
	| "javascript"
	| "node"
	| "ruby"
	| "perl"
	| "php"
	| "unknown";

export type HeredocClassification = "readonly" | "modify" | "unknown";

export interface HeredocAnalysis {
	language: HeredocLanguage;
	classification: HeredocClassification;
	confidence: "high" | "medium" | "low";
	reasoning: string;
	writeOperations: string[];
	heredocContent: string;
}

/**
 * Detect the language of a heredoc from its delimiter.
 */
export function detectHeredocLanguage(delimiter: string): HeredocLanguage {
	const lower = delimiter.toLowerCase();

	// Common language-specific delimiters
	if (lower === "py" || lower === "python") return "python";
	if (lower === "bash" || lower === "sh" || lower === "shell") return "bash";
	if (lower === "js" || lower === "javascript") return "javascript";
	if (lower === "rb" || lower === "ruby") return "ruby";
	if (lower === "pl" || lower === "perl") return "perl";
	if (lower === "php") return "php";

	// Default to bash for unknown delimiters
	return "bash";
}

/**
 * Extract heredocs from a shell command.
 * Returns array of { delimiter, language, content }.
 */
export function extractHeredocs(command: string): Array<{
	delimiter: string;
	language: HeredocLanguage;
	content: string;
}> {
	const heredocs: Array<{ delimiter: string; language: HeredocLanguage; content: string }> = [];

	// Match heredoc patterns: <<'DELIM' or <<DELIM or <<-DELIM
	const heredocPattern = /<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*\n([\s\S]*?)\n\1/g;

	let match;
	while ((match = heredocPattern.exec(command)) !== null) {
		const delimiter = match[1];
		const content = match[2];
		const language = detectHeredocLanguage(delimiter);
		heredocs.push({ delimiter, language, content });
	}

	return heredocs;
}

/**
 * Python write operation patterns.
 */
const PYTHON_WRITE_PATTERNS = [
	/\bopen\s*\(\s*[^)]+,\s*['"](w|a|r\+|w\+|a\+)['"]/i, // open(f, 'w'), open(f, 'a')
	/\bopen\s*\([^)]*\)\s*\.\s*write\s*\(/i, // open(f).write()
	/\bwith\s+open\s*\(\s*[^)]+,\s*['"](w|a|r\+|w\+|a\+)['"]/i, // with open(f, 'w')
	/\bos\.(remove|unlink|rmdir)\s*\(/i,
	/\bshutil\.(rmtree|move|copy|copy2)\s*\(/i,
	/\bos\.makedirs?\s*\(/i,
	/\bpathlib\.Path\s*\([^)]*\)\.\s*(write_text|unlink|rmdir)\s*\(/i,
	/\bsubprocess\.(run|call|Popen)\s*\(.*\b(rm|mv|cp|mkdir|rmdir|chmod|chown)\b/i,
	/\brequests\.(post|put|patch|delete)\s*\(/i,
	/\bhttpx\.(post|put|patch|delete)\s*\(/i,
	/\burllib\.request\.(urlopen|Request).*\b(?:(?:POST|PUT|DELETE|PATCH))\b/i,
];

/**
 * Python readonly indicators (confirm safety).
 */
const PYTHON_READONLY_PATTERNS = [
	/\bopen\s*\(\s*[^)]+,\s*['"]r['"]?\s*\)/i, // open(f, 'r')
	/\brequests\.get\s*\(/i,
	/\bhttpx\.get\s*\(/i,
	/\bprint\s*\(/i,
	/\bjson\.(load|loads)\s*\(/i,
	/\bre\.(search|match|findall)\s*\(/i,
];

/**
 * Bash write operation patterns.
 */
const BASH_WRITE_PATTERNS = [
	/>\s*[^>&]/, // > file (but not >& or >>)
	/>>/, // >> file
	/\bsed\s+.*-i\b/, // sed -i (in-place edit)
	/\brm\s/, // rm
	/\bmv\s/, // mv
	/\bcp\s/, // cp (creates files)
	/\bmkdir\s/, // mkdir
	/\btouch\s/, // touch
	/\bchmod\s/, // chmod
	/\bchown\s/, // chchown
	/\btruncate\s/, // truncate
	/\bdd\s+.*of=/, // dd of=file
	/\btee\s/, // tee (writes)
	/\binstall\s/, // install (copies)
	/\bcurl\s+.*-[odX]\s/, // curl -O, -d, -X POST/PUT/DELETE
	/\bwget\s+.*--post/i, // wget --post-data
	/\bflock\s+.*[wx]/, // flock with write lock
];

/**
 * Bash readonly indicators.
 */
const BASH_READONLY_PATTERNS = [
	/\bcat\s/,
	/\bhead\s/,
	/\btail\s/,
	/\bgrep\s/,
	/\bfind\s/,
	/\bls\s/,
	/\becho\b(?!\s*[>&])/, // echo without redirection
	/\bread\s/, // read (input)
	/\bwc\s/,
	/\bsort\s/,
	/\bawk\s+.*\b(print|printf)\b/,
	/\bsed\s+.*\bp\b/, // sed -n (no in-place)
	/\bcurl\s/, // curl (downloads, typically considered readonly)
];

/**
 * JavaScript/Node write patterns.
 */
const JS_WRITE_PATTERNS = [
	/\bfs\.(writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rmdir|mkdir)\s*\(/i,
	/\bfs\.(createWriteStream|openSync)\s*\(/i,
	/\bfs\.promises\.(writeFile|unlink|mkdir)\s*\(/i,
	/\bfs\.write\s*\(/i,
	/child_process.*\.(spawn|exec|execFile).*\b(rm|mv|cp|mkdir|touch)\b/i,
	/\bfetch\s*\([^)]+,\s*\{[^}]*method:\s*['"](POST|PUT|DELETE|PATCH)['"]/i,
	/\baxios\.(post|put|patch|delete)\s*\(/i,
];

/**
 * JavaScript readonly patterns.
 */
const JS_READONLY_PATTERNS = [
	/\bfs\.(readFile|readdir|stat|exists|access)\s*\(/i,
	/\bfs\.(createReadStream|open)\s*\(\s*[^)]+,\s*['"]r['"]?\)/i,
	/\bconsole\.(log|info|warn|error)\s*\(/i,
	/\bfetch\s*\([^)]*\)\s*(?!,\s*\{[^}]*method:\s*['"](POST|PUT|DELETE|PATCH)['"])/i, // fetch() without method
	/\bJSON\.(parse|stringify)\s*\(/i,
];

/**
 * Ruby write patterns.
 */
const RUBY_WRITE_PATTERNS = [
	/\bFile\.write\s*\(/i, // File.write directly writes
	/\bFile\.(open)\s*\([^)]+,\s*['"](w|a)['"]/i, // File.open with mode
	/\bFileUtils\.(rm|rm_rf|rm_r|mv|cp|mkdir|makedirs)\s*\(/i,
	/\bFile\.(delete|unlink)\s*\(/i,
	/\bDir\.(mkdir|rmdir)\s*\(/i,
];

/**
 * Ruby readonly patterns.
 */
const RUBY_READONLY_PATTERNS = [
	/\bFile\.(read|readlines|open)\s*\([^)]+\)\s*(?!\s*\{|,\s*['"]w['"])/i,
	/\bFile\.(exist\?|file\?|directory\?)\s*\(/i,
	/\bputs\s+/,
	/\bp\s+/,
];

/**
 * Perl write patterns.
 */
const PERL_WRITE_PATTERNS = [
	/\bopen\s*\([^)]+,\s*['"](>|>>|\+>|\+>>)['"]\s*,/i,
	/\bunlink\b/i, // unlink can be called with or without parens
	/\brename\s*\(/i,
	/\bmkdir\b/i,
	/\brmdir\b/i,
	/\bsystem\s*\([^)]*\b(rm|mv|cp|mkdir|chmod)\b/i,
];

/**
 * Perl readonly patterns.
 */
const PERL_READONLY_PATTERNS = [
	/\bopen\s*\([^)]+,\s*['"]<['"]?\s*,/i, // open(F, "<", file)
	/\bopen\s*\([^)]+,\s*['"]['"]?\s*,/i, // open(F, file) - default is read
	/\bprint\s+/,
	/\bsay\s+/,
	/\bwhile\s*\(\s*<[^>]+>\s*\)/i, // while (<STDIN>)
];

/**
 * Classify heredoc content using pattern matching.
 * Fast, deterministic classification for common cases.
 */
export function classifyHeredoc(
	content: string,
	language: HeredocLanguage,
): { classification: HeredocClassification; confidence: "high" | "medium" | "low"; reasoning: string; writeOperations: string[] } {
	const writeOperations: string[] = [];
	let hasWrite = false;
	let hasReadonly = false;

	// Language-specific pattern matching
	switch (language) {
		case "python": {
			for (const pattern of PYTHON_WRITE_PATTERNS) {
				const match = content.match(pattern);
				if (match) {
					hasWrite = true;
					writeOperations.push(match[0].trim().slice(0, 50));
				}
			}
			for (const pattern of PYTHON_READONLY_PATTERNS) {
				if (pattern.test(content)) {
					hasReadonly = true;
				}
			}
			break;
		}

		case "bash": {
			for (const pattern of BASH_WRITE_PATTERNS) {
				const match = content.match(pattern);
				if (match) {
					hasWrite = true;
					writeOperations.push(match[0].trim().slice(0, 50));
				}
			}
			for (const pattern of BASH_READONLY_PATTERNS) {
				if (pattern.test(content)) {
					hasReadonly = true;
				}
			}
			break;
		}

		case "javascript":
		case "node": {
			for (const pattern of JS_WRITE_PATTERNS) {
				const match = content.match(pattern);
				if (match) {
					hasWrite = true;
					writeOperations.push(match[0].trim().slice(0, 50));
				}
			}
			for (const pattern of JS_READONLY_PATTERNS) {
				if (pattern.test(content)) {
					hasReadonly = true;
				}
			}
			break;
		}

		case "ruby": {
			for (const pattern of RUBY_WRITE_PATTERNS) {
				const match = content.match(pattern);
				if (match) {
					hasWrite = true;
					writeOperations.push(match[0].trim().slice(0, 50));
				}
			}
			for (const pattern of RUBY_READONLY_PATTERNS) {
				if (pattern.test(content)) {
					hasReadonly = true;
				}
			}
			break;
		}

		case "perl": {
			for (const pattern of PERL_WRITE_PATTERNS) {
				const match = content.match(pattern);
				if (match) {
					hasWrite = true;
					writeOperations.push(match[0].trim().slice(0, 50));
				}
			}
			for (const pattern of PERL_READONLY_PATTERNS) {
				if (pattern.test(content)) {
					hasReadonly = true;
				}
			}
			break;
		}

		default: {
			// Unknown language - check for common dangerous patterns
			if (/\b(rm\s|mv\s|mkdir\s|>\s|>>)/.test(content)) {
				hasWrite = true;
				writeOperations.push("Generic write pattern detected");
			}
			break;
		}
	}

	// Determine classification
	if (hasWrite) {
		return {
			classification: "modify",
			confidence: writeOperations.length > 0 ? "high" : "medium",
			reasoning: `Write operations detected: ${writeOperations.slice(0, 3).join(", ")}`,
			writeOperations,
		};
	}

	if (hasReadonly) {
		return {
			classification: "readonly",
			confidence: "high",
			reasoning: "Only readonly operations detected (print, read, get requests)",
			writeOperations: [],
		};
	}

	// No clear patterns - check for obvious readonly behavior
	if (language === "python" && /\bprint\s*\(/.test(content) && !PYTHON_WRITE_PATTERNS.some((p) => p.test(content))) {
		return {
			classification: "readonly",
			confidence: "medium",
			reasoning: "Only prints output, no write patterns detected",
			writeOperations: [],
		};
	}

	if (language === "bash" && /\becho\s+/.test(content) && !BASH_WRITE_PATTERNS.some((p) => p.test(content))) {
		return {
			classification: "readonly",
			confidence: "medium",
			reasoning: "Only echoes output, no write patterns detected",
			writeOperations: [],
		};
	}

	return {
		classification: "unknown",
		confidence: "low",
		reasoning: "Unable to confidently classify - manual review recommended",
		writeOperations: [],
	};
}

/**
 * Full heredoc analysis for a command.
 * Extracts and classifies all heredocs in the command.
 */
export function analyzeHeredocs(command: string): HeredocAnalysis[] {
	const heredocs = extractHeredocs(command);

	return heredocs.map(({ delimiter, language, content }) => {
		const analysis = classifyHeredoc(content, language);
		return {
			language,
			classification: analysis.classification,
			confidence: analysis.confidence,
			reasoning: analysis.reasoning,
			writeOperations: analysis.writeOperations,
			heredocContent: content,
		};
	});
}

/**
 * Get overall risk level from heredoc analyses.
 * Returns the highest risk level found.
 */
export function getOverallHeredocRisk(analyses: HeredocAnalysis[]): HeredocClassification {
	if (analyses.some((a) => a.classification === "modify")) {
		return "modify";
	}
	if (analyses.some((a) => a.classification === "unknown")) {
		return "unknown";
	}
	return "readonly";
}

/**
 * Format heredoc analysis for display in approval prompts.
 */
export function formatHeredocAnalysis(analyses: HeredocAnalysis[]): string {
	if (analyses.length === 0) return "";

	const lines: string[] = ["Heredoc Analysis:"];

	for (const analysis of analyses) {
		const icon = analysis.classification === "readonly" ? "✓" : analysis.classification === "modify" ? "⚠" : "?";
		const confidence = analysis.confidence === "high" ? "" : ` (${analysis.confidence} confidence)`;
		lines.push(`  ${icon} ${analysis.language}: ${analysis.classification}${confidence}`);
		if (analysis.writeOperations.length > 0) {
			lines.push(`    Write ops: ${analysis.writeOperations.slice(0, 3).join(", ")}`);
		}
		if (analysis.reasoning) {
			lines.push(`    ${analysis.reasoning}`);
		}
	}

	return lines.join("\n");
}