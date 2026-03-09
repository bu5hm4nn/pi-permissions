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
		// Only block if SSH is actually detected via text search.
		const result = legacyDirectSshFamilyMatchDetailed(command);
		// Only block if SSH was detected, not for parse failures
		return result.blocked && result.reason === 'ssh_detected';
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

	// Only block if SSH was actually detected.
	// Parser uncertainty without detected SSH → pass through to bash permissions logic.
	if (state.blocked) return true;
	return false;
}
