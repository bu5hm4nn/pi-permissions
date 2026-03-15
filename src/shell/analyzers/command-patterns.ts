import { walkShellAst } from "../parser/ast-walk.ts";
import { parseShell } from "../parser/parse.ts";
import { extractLiteralCommandNodeParts } from "../parser/command-node.ts";
import { resolveHeadFromLiterals } from "../parser/resolve-head.ts";
import { normalizeLiteralToken } from "../parser/tokens.ts";
import { STANDARD_WRAPPERS as WRAPPERS } from "../parser/wrappers.ts";
import { extractCurlMethodPatterns } from "./curl-patterns.ts";
import { extractDockerShellPatterns } from "./docker-patterns.ts";
import { extractWgetMethodPatterns } from "./wget-patterns.ts";

const SUBCOMMAND_MATCH_COMMANDS = new Set([
	"docker",
	"docker-compose",
	"kubectl",
	"git",
	"npm",
	"pnpm",
	"yarn",
	"gh",
	"glab",
	"helm",
]);

export interface CommandPatternAnalysis {
	patterns: string[];
	complete: boolean;
	reason?: string;
}

// Informational docker commands/flags that are safe with specific patterns
const DOCKER_INFO_COMMANDS = new Set(["--version", "-v", "--help", "-h", "version", "info"]);

// Informational docker subcommand commands (e.g., "docker compose version")
const DOCKER_SUBCOMMAND_INFO_COMMANDS = new Set(["version", "info", "help"]);

function maybeSubcommand(executable: string, args: string[]): { name: string | null; argOffset: number } {
	if (!SUBCOMMAND_MATCH_COMMANDS.has(executable.toLowerCase())) return { name: null, argOffset: 0 };
	if (args.length === 0) return { name: null, argOffset: 0 };
	
	// Skip flags to find the actual subcommand.
	// Flags with values (e.g., --context prod) are tricky - we use a list of known value-taking flags
	// to avoid skipping the subcommand. For unknown flags, we conservatively skip only the flag itself.
	const FLAGS_WITH_VALUES = new Set([
		// Docker flags with values
		"--context", "-c", "--log-level", "-l", "--config",
		// Git flags with values
		"-C", "--git-dir", "--work-tree", "-c",
		// kubectl flags with values
		"--context", "--cluster", "--user", "--namespace", "-n", "--server", "--kubeconfig",
		// npm/yarn/pnpm flags with values
		"--registry", "--scope", "--tag", "-g",
		// Common flags with values
		"--output", "-o", "--format", "-f", "--file", "-F", "--directory", "-C",
	]);
	
	let i = 0;
	while (i < args.length) {
		const arg = args[i];
		if (arg === "--") {
			// End of options
			i++;
			break;
		}
		if (arg.startsWith("-")) {
			// It's a flag - check if it takes a value
			const flagBase = arg.includes("=") ? arg.split("=")[0] : arg;
			if (FLAGS_WITH_VALUES.has(flagBase)) {
				// Skip flag and its value
				i += 2;
			} else {
				// Boolean/unknown flag - skip only the flag
				i += 1;
			}
			continue;
		}
		// Found non-flag argument - this is the subcommand
		break;
	}
	
	if (i >= args.length) return { name: null, argOffset: 0 };
	const subcommand = normalizeLiteralToken(args[i]);
	if (!subcommand) return { name: null, argOffset: 0 };
	return { name: subcommand, argOffset: i + 1 };
}

function extractCommandPattern(node: any, depth: number): { patterns: string[]; complete: boolean } {
	const extracted = extractLiteralCommandNodeParts(node);
	if (!extracted.complete) return { patterns: [], complete: false };

	const resolvedHead = resolveHeadFromLiterals(extracted.headText, extracted.suffixLiterals, WRAPPERS);
	if (!resolvedHead.complete) return { patterns: [], complete: false };

	const executable = resolvedHead.head;
	const argIndex = resolvedHead.argIndex;
	const args = extracted.suffixLiterals.slice(argIndex);
	const subcommand = maybeSubcommand(executable, args);
	
	// Handle docker without subcommand
	if (executable.toLowerCase() === "docker" && !subcommand.name) {
		// Check for informational flags like --version, -v, --help
		const firstArg = args[0];
		if (firstArg && DOCKER_INFO_COMMANDS.has(firstArg)) {
			return { patterns: [`docker ${firstArg}`], complete: true };
		}
		// Unknown docker command without subcommand - still allow with wildcard
		return { patterns: ["docker *"], complete: true };
	}

	const curlPatterns = executable.toLowerCase() === "curl" ? extractCurlMethodPatterns(args) : null;
	const wgetPatterns = executable.toLowerCase() === "wget" ? extractWgetMethodPatterns(args) : null;
	
	// Build base pattern
	let basePatterns: string[];
	if (curlPatterns) {
		basePatterns = curlPatterns.patterns;
	} else if (wgetPatterns) {
		basePatterns = wgetPatterns.patterns;
	} else if (subcommand.name) {
		// Check for informational docker subcommand commands (e.g., "docker compose version")
		// Only apply this logic for docker, not other subcommand-capable CLIs
		if (executable.toLowerCase() === "docker") {
			const subcommandArg = args[subcommand.argOffset];
			if (DOCKER_SUBCOMMAND_INFO_COMMANDS.has(subcommandArg)) {
				basePatterns = [`${executable} ${subcommand.name} ${subcommandArg}`];
			} else {
				basePatterns = [`${executable} ${subcommand.name} *`];
			}
		} else {
			basePatterns = [`${executable} ${subcommand.name} *`];
		}
	} else {
		basePatterns = [`${executable} *`];
	}
	const patterns = [...basePatterns];

	if (executable.toLowerCase() === "docker" && (subcommand.name === "run" || subcommand.name === "exec")) {
		const nested = extractDockerShellPatterns(args.slice(subcommand.argOffset), subcommand.name, depth, (payload) =>
			analyzeCommandPatternsInternal(payload, depth + 1),
		);
		if (!nested.complete) return { patterns, complete: false };
		for (const p of nested.patterns) patterns.push(`docker(${subcommand.name}): ${p}`);
	}

	if (curlPatterns && !curlPatterns.complete) return { patterns, complete: false };
	if (wgetPatterns && !wgetPatterns.complete) return { patterns, complete: false };
	return { patterns, complete: true };
}

function analyzeCommandPatternsInternal(command: string, depth: number): CommandPatternAnalysis {
	if (depth > 2) return { patterns: [], complete: false, reason: "max_recursion_depth" };

	const parsed = parseShell(command);
	if (parsed.certainty !== "resolved" || !parsed.ast) {
		return { patterns: [], complete: false, reason: parsed.error ?? "bash_parser_unavailable" };
	}

	const patterns: string[] = [];
	const seen = new Set<string>();
	const state = { complete: true };
	walkShellAst(parsed.ast, {
		onCommand(node) {
			const resolved = extractCommandPattern(node, depth);
			if (!resolved.complete) state.complete = false;
			for (const pattern of resolved.patterns) {
				if (!seen.has(pattern)) {
					seen.add(pattern);
					patterns.push(pattern);
				}
			}
		},
		onFunction() {
			state.complete = false;
		},
		onUnknown() {
			state.complete = false;
		},
	});
	if (patterns.length === 0) {
		return { patterns, complete: false, reason: "no_static_commands" };
	}
	return { patterns, complete: state.complete };
}

export function analyzeCommandPatterns(command: string): CommandPatternAnalysis {
	try {
		return analyzeCommandPatternsInternal(command, 0);
	} catch (e) {
		return {
			patterns: [],
			complete: false,
			reason: e instanceof Error ? e.message : String(e),
		};
	}
}

function formatPatternExample(pattern: string): string | null {
	const parts = pattern.split(" ");
	if (parts.length >= 3 && parts[0] === "wget") {
		const method = parts[1];
		const scope = parts.slice(2).join(" ");
		const urlPart = scope === "*" ? "https://api.example.com/..." : scope.replace(/\*$/, "...");
		if (method === "POST") return `wget --post-data=... ${urlPart}`;
		if (method === "DELETE") return `wget --method=DELETE ${urlPart}`;
		if (method === "PUT") return `wget --method=PUT ${urlPart}`;
		if (method === "PATCH") return `wget --method=PATCH ${urlPart}`;
	}
	if (parts.length >= 3 && parts[0] === "curl") {
		const method = parts[1];
		const scope = parts.slice(2).join(" ");
		const urlPart = scope === "*" ? "https://api.example.com/..." : scope.replace(/\*$/, "...");
		if (method !== "GET" && method !== "HEAD") return `curl -X ${method} ${urlPart}`;
	}
	return null;
}

export function getFallbackPattern(pattern: string): string | null {
	if (!pattern) return null;
	if (pattern.endsWith(" *")) return null;
	const parts = pattern.split(" ");
	if (parts.length >= 3 && (parts[0] === "curl" || parts[0] === "wget")) {
		// e.g. "curl POST https://api.example.com" -> "curl POST *"
		return `${parts[0]} ${parts[1]} *`;
	}
	return null;
}

export function formatAllowPatternSummary(patterns: string[], maxItems = 8): string {
	if (patterns.length === 0) return "";
	const shownPatterns = patterns.slice(0, maxItems);
	const shown = shownPatterns.map((p) => `\"${p}\"`);
	const extra = patterns.length > maxItems ? `, +${patterns.length - maxItems} more` : "";
	const base = `${shown.join(", ")}${extra}`;
	if (shownPatterns.length !== 1) return base;
	const example = formatPatternExample(shownPatterns[0]);
	return example ? `${base} (e.g., ${example})` : base;
}
