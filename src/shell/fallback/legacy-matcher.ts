import { stripHeredocBodiesForLegacyParsing } from "./heredoc.ts";
import { isEnvAssignmentToken, normalizeExecutableToken } from "../parser/tokens.ts";
import { SSH_MATCHER_WRAPPERS as DEFAULT_WRAPPERS, stepWrapper } from "../parser/wrappers.ts";

const DEFAULT_BLOCKED = new Set(["ssh", "scp", "sftp", "sshpass", "mosh"]);

export function legacySplitCommandSegments(command: string): string[] | null {
	const out: string[] = [];
	let cur = "";
	let quote: '"' | "'" | null = null;
	let escaped = false;
	let sawSeparator = false;
	let trailingCriticalSeparator = false;

	for (let i = 0; i < command.length; i++) {
		const ch = command[i];
		if (escaped) {
			cur += ch;
			escaped = false;
			continue;
		}
		if (ch === "\\" && quote !== "'") {
			cur += ch;
			escaped = true;
			continue;
		}
		if (quote) {
			cur += ch;
			if (ch === quote) quote = null;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			cur += ch;
			continue;
		}
		if (ch === "#") {
			while (i < command.length && command[i] !== "\n") i++;
			i--;
			continue;
		}

		const next = command[i + 1] || "";
		const isDoubleOp = (ch === "&" && next === "&") || (ch === "|" && next === "|");
		if (ch === ";" || ch === "\n" || ch === "|" || ch === "&" || isDoubleOp) {
			const trimmed = cur.trim();
			if (trimmed) out.push(trimmed);
			cur = "";
			sawSeparator = true;
			trailingCriticalSeparator = isDoubleOp || ch === "|" || ch === "&";
			if (isDoubleOp) i++;
			continue;
		}

		cur += ch;
	}

	if (escaped || quote) return null;
	const trimmed = cur.trim();
	if (trimmed) {
		out.push(trimmed);
		return out;
	}
	if (trailingCriticalSeparator) return null;
	if (sawSeparator) return out;
	return out;
}

export function legacyTokenizeSegment(segment: string): string[] | null {
	const out: string[] = [];
	let cur = "";
	let quote: '"' | "'" | null = null;
	let escaped = false;

	for (let i = 0; i < segment.length; i++) {
		const ch = segment[i];
		if (escaped) {
			cur += ch;
			escaped = false;
			continue;
		}
		if (ch === "\\" && quote !== "'") {
			cur += ch;
			escaped = true;
			continue;
		}
		if (quote) {
			cur += ch;
			if (ch === quote) quote = null;
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			cur += ch;
			continue;
		}
		if (/\s/.test(ch)) {
			if (cur) out.push(cur);
			cur = "";
			continue;
		}
		cur += ch;
	}

	if (escaped || quote) return null;
	if (cur) out.push(cur);
	return out;
}

export function legacyResolveHead(
	tokens: string[],
	wrappers: ReadonlySet<string> = DEFAULT_WRAPPERS,
): string | null {
	if (tokens.length === 0) return null;
	let i = 0;
	while (i < tokens.length && isEnvAssignmentToken(tokens[i])) i++;
	if (i >= tokens.length) return "";
	while (i < tokens.length) {
		const token = normalizeExecutableToken(tokens[i], { lowercase: true });
		if (!token) return null;
		if (!wrappers.has(token)) return token;
		i++;
		const next = stepWrapper(token, tokens, i);
		if (next === null) return null;
		i = next;
	}
	return null;
}

function cleanupTokenForKeywordMatch(token: string): string {
	let t = token.trim();
	t = t.replace(/^[^A-Za-z0-9_./-]+/, "");
	t = t.replace(/[^A-Za-z0-9_./-]+$/, "");
	return t;
}

export function legacyDirectSshFamilyMatch(
	command: string,
	options: { blocked?: ReadonlySet<string>; wrappers?: ReadonlySet<string> } = {},
): boolean {
	const blocked = options.blocked ?? DEFAULT_BLOCKED;
	const wrappers = options.wrappers ?? DEFAULT_WRAPPERS;
	const sanitized = stripHeredocBodiesForLegacyParsing(command);
	const segments = legacySplitCommandSegments(sanitized);
	if (!segments) return true;
	for (const seg of segments) {
		const tokens = legacyTokenizeSegment(seg);
		if (!tokens) return true;
		const head = legacyResolveHead(tokens, wrappers);
		if (head === null) return true;
		if (head && blocked.has(head)) return true;

		for (const token of tokens) {
			const cleaned = cleanupTokenForKeywordMatch(token);
			if (!cleaned) continue;
			const maybe = normalizeExecutableToken(cleaned, { lowercase: true });
			if (maybe && blocked.has(maybe)) return true;
		}
	}
	return false;
}

export { stripHeredocBodiesForLegacyParsing };
