// bash-parser is a CommonJS package.
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import parseBashModule from "bash-parser";
import type { ParseShellResult } from "./types.ts";
import { stripHeredocBodies } from "./heredoc-preprocess.ts";

export const parseBash: ((source: string) => any) | undefined =
	typeof parseBashModule === "function" ? parseBashModule : (parseBashModule as any)?.default;

export function parseShell(source: string): ParseShellResult {
	if (typeof parseBash !== "function") {
		return { ast: null, certainty: "uncertain", error: "bash_parser_unavailable" };
	}
	try {
		// Preprocess to strip heredoc content - the parser doesn't handle non-shell
		// languages inside heredocs (Python, JS, etc.) and will fail on them.
		const preprocessed = stripHeredocBodies(source);
		return { ast: parseBash(preprocessed), certainty: "resolved" };
	} catch (error) {
		return {
			ast: null,
			certainty: "uncertain",
			error: error instanceof Error ? error.message : String(error),
		};
	}
}
