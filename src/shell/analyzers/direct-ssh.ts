import { walkShellAst } from "../parser/ast-walk.ts";
import { parseShell } from "../parser/parse.ts";
import { extractLiteralCommandNodeParts } from "../parser/command-node.ts";
import { resolveHeadFromLiterals } from "../parser/resolve-head.ts";
import { SSH_MATCHER_WRAPPERS as WRAPPERS } from "../parser/wrappers.ts";

const BLOCKED = new Set(["ssh", "scp", "sftp", "sshpass", "mosh"]);

export const DIRECT_SSH_PARSE_FAILURE_MODE = "strict" as const;

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
		return true;
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

	if (state.blocked) return true;
	if (state.uncertain) return true;
	return false;
}
