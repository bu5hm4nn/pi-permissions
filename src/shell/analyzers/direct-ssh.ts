import { walkShellAst } from "../parser/ast-walk.ts";
import { parseShell } from "../parser/parse.ts";
import { extractLiteralCommandNodeParts } from "../parser/command-node.ts";
import { resolveHeadFromLiterals } from "../parser/resolve-head.ts";
import { SSH_MATCHER_WRAPPERS as WRAPPERS } from "../parser/wrappers.ts";
import { legacyDirectSshFamilyMatchDetailed } from "../fallback/legacy-matcher.ts";

const BLOCKED = new Set(["ssh", "scp", "sftp", "sshpass", "mosh"]);

/**
 * Result type for detailed SSH-family command detection.
 * - `blocked: true, reason: 'ssh_detected'` - SSH-family command found
 * - `blocked: true, reason: 'parse_failure'` - Parse error, couldn't confirm no SSH
 * - `blocked: true, reason: 'uncertain'` - Parser uncertainty (functions, unknown constructs)
 * - `blocked: false, reason: undefined` - No SSH-family command detected
 */
export type SshCheckResult = { blocked: boolean; reason?: "ssh_detected" | "parse_failure" | "uncertain" };

function resolveExecutable(commandNode: any): { head: string; complete: boolean } {
	if (!commandNode?.name) return { head: "", complete: true };

	const extracted = extractLiteralCommandNodeParts(commandNode);
	if (!extracted.complete) return { head: "", complete: false };

	const resolved = resolveHeadFromLiterals(extracted.headText, extracted.suffixLiterals, WRAPPERS, { lowercase: true });
	return { head: resolved.head, complete: resolved.complete };
}

/**
 * Check if a command contains a direct SSH-family invocation and return detailed reason.
 * This is the detailed version that provides the specific reason for blocking.
 */
export function isDirectSshFamilyCommandDetailed(command: string): SshCheckResult {
	const parsed = parseShell(command);
	if (parsed.certainty !== "resolved" || !parsed.ast) {
		// Parser couldn't produce a resolved AST - FAIL-CLOSED behavior.
		// Delegate to legacy matcher to check for SSH, but enforce fail-closed:
		// - Preserve ssh_detected if legacy matcher positively detects SSH
		// - Otherwise return parse_failure (couldn't confirm no SSH)
		const result = legacyDirectSshFamilyMatchDetailed(command);
		if (result.reason === "ssh_detected") {
			return { blocked: true, reason: "ssh_detected" };
		}
		return { blocked: true, reason: "parse_failure" };
	}

	const state = { blocked: false, uncertain: false };
	walkShellAst(parsed.ast, {
		shouldStop: () => state.blocked,
		onCommand(commandNode) {
			const resolved = resolveExecutable(commandNode);
			if (!resolved.complete) {
				state.uncertain = true;
				return;
			}
			if (resolved.head && BLOCKED.has(resolved.head)) {
				state.blocked = true;
			}
		},
		onFunction() {
			state.uncertain = true;
		},
		onUnknown() {
			state.uncertain = true;
		},
	});

	// Block if SSH was detected
	if (state.blocked) {
		return { blocked: true, reason: "ssh_detected" };
	}

	// AST-walk uncertainty on resolved AST: block as uncertain
	// (functions, dynamic executables, unknown constructs)
	if (state.uncertain) {
		return { blocked: true, reason: "uncertain" };
	}

	return { blocked: false, reason: undefined };
}

/**
 * Boolean version of SSH-family command detection.
 * Returns true if the command should be blocked, false otherwise.
 */
export function isDirectSshFamilyCommand(command: string): boolean {
	const result = isDirectSshFamilyCommandDetailed(command);
	return result.blocked;
}