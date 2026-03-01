import { normalizeExecutableToken } from "./tokens.ts";
import { stepWrapper } from "./wrappers.ts";

export interface ResolveHeadFromLiteralsResult {
	head: string;
	complete: boolean;
	argIndex: number;
}

export interface ResolveHeadFromLiteralsOptions {
	lowercase?: boolean;
}

export function resolveHeadFromLiterals(
	headLiteral: string,
	suffixLiterals: string[],
	wrappers: Set<string>,
	options?: ResolveHeadFromLiteralsOptions,
): ResolveHeadFromLiteralsResult {
	let executable = normalizeExecutableToken(headLiteral, options);
	if (!executable) return { head: "", complete: false, argIndex: 0 };
	if (!wrappers.has(executable)) return { head: executable, complete: true, argIndex: 0 };

	let argIndex = 0;
	while (wrappers.has(executable)) {
		const next = stepWrapper(executable, suffixLiterals, argIndex);
		if (next === null || next >= suffixLiterals.length) return { head: "", complete: false, argIndex: 0 };
		const inner = normalizeExecutableToken(suffixLiterals[next], options);
		if (!inner) return { head: "", complete: false, argIndex: 0 };
		executable = inner;
		argIndex = next + 1;
	}

	return { head: executable, complete: true, argIndex };
}
