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

function maybeSubcommand(executable: string, args: string[]): { name: string | null; argOffset: number } {
	if (!SUBCOMMAND_MATCH_COMMANDS.has(executable.toLowerCase())) return { name: null, argOffset: 0 };
	if (args.length === 0) return { name: null, argOffset: 0 };
	const first = normalizeLiteralToken(args[0]);
	if (!first) return { name: null, argOffset: 0 };
	if (first === "--" || first.startsWith("-")) return { name: null, argOffset: 0 };
	return { name: first, argOffset: 1 };
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
	if (executable.toLowerCase() === "docker" && !subcommand.name) {
		return { patterns: [], complete: false };
	}

	const curlPatterns = executable.toLowerCase() === "curl" ? extractCurlMethodPatterns(args) : null;
	const wgetPatterns = executable.toLowerCase() === "wget" ? extractWgetMethodPatterns(args) : null;
	const basePatterns = curlPatterns
		? curlPatterns.patterns
		: wgetPatterns
			? wgetPatterns.patterns
			: [subcommand.name ? `${executable} ${subcommand.name} *` : `${executable} *`];
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
	if (pattern === "wget POST *") return "wget --post-data=... https://api.example.com/...";
	if (pattern === "wget DELETE *") return "wget --method=DELETE https://api.example.com/...";
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
