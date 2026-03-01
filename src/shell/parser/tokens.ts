export function decodeEscapes(text: string): string | null {
	let out = "";
	for (let i = 0; i < text.length; i++) {
		const ch = text[i];
		if (ch !== "\\") {
			out += ch;
			continue;
		}
		if (i + 1 >= text.length) return null;
		out += text[i + 1];
		i++;
	}
	return out;
}

export function literalWordText(node: any): string | null {
	if (!node || node.type !== "Word") return null;
	if (Array.isArray(node.expansion) && node.expansion.length > 0) return null;
	if (typeof node.text !== "string") return null;
	return node.text;
}

export function isEnvAssignmentToken(token: string): boolean {
	return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(token);
}

export function stripMatchingQuotes(text: string): string {
	if (text.length >= 2 && ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'")))) {
		return text.slice(1, -1);
	}
	return text;
}

export function normalizeExecutableToken(text: string, options?: { lowercase?: boolean }): string | null {
	const trimmed = text.trim();
	if (!trimmed || /\s/.test(trimmed)) return null;
	const decoded = decodeEscapes(trimmed);
	if (!decoded || decoded.startsWith("-")) return null;
	const idx = decoded.lastIndexOf("/");
	const base = idx >= 0 ? decoded.slice(idx + 1) : decoded;
	return options?.lowercase ? base.toLowerCase() : base;
}

export function normalizeLiteralToken(text: string): string | null {
	const trimmed = text.trim();
	if (!trimmed || /\s/.test(trimmed)) return null;
	const unquoted = stripMatchingQuotes(trimmed);
	if (!unquoted || /\s/.test(unquoted)) return null;
	return unquoted;
}

export function decodeLiteralText(text: string): string | null {
	const trimmed = text.trim();
	if (!trimmed) return null;
	const decoded = decodeEscapes(trimmed);
	if (!decoded) return null;
	return stripMatchingQuotes(decoded);
}
