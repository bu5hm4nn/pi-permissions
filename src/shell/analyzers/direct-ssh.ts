import { walkShellAst } from "../parser/ast-walk.ts";
import { parseShell } from "../parser/parse.ts";
import { extractLiteralCommandNodeParts } from "../parser/command-node.ts";
import { resolveHeadFromLiterals } from "../parser/resolve-head.ts";
import { SSH_MATCHER_WRAPPERS as WRAPPERS } from "../parser/wrappers.ts";
import { legacyDirectSshFamilyMatchDetailed } from "../fallback/legacy-matcher.ts";

const BLOCKED = new Set(["ssh", "scp", "sftp", "sshpass", "mosh"]);

function resolveExecutable(commandNode: any): { head: string; complete: boolean } {
	if (!commandNode?.name) return { head: "", complete: true };

	const extracted = extractLiteralCommandNodeParts(commandNode);
	if (!extracted.complete) return { head: "", complete: false };

	const resolved = resolveHeadFromLiterals(extracted.headText, extracted.suffixLiterals, WRAPPERS, { lowercase: true });
	return { head: resolved.head, complete: resolved.complete };
}

export function isDirectSshFamilyCommand(command: string): boolean {
	const parsed = parseShell(command);
	if (parsed.certainty !== "resolved" || !parsed.ast) {
		// Parse failure: use legacy text-based matcher as fallback.
		// This handles cases like process substitution `<(...)` that the parser can't handle.
		// Fail-closed: block if SSH detected OR if we can't parse and can't confirm no SSH.
		const result = legacyDirectSshFamilyMatchDetailed(command);
		// Block if SSH detected (ssh_detected) or parse failure (can't confirm no SSH)
		return result.blocked;
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

	// Block if SSH was detected OR if there's parser uncertainty (fail-closed)
	if (state.blocked) return true;
	if (state.uncertain) {
		// Parser uncertainty with no SSH detected - use legacy matcher for final decision
		const result = legacyDirectSshFamilyMatchDetailed(command);
		return result.blocked;
	}
	return false;
}
