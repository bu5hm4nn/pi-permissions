import { decodeLiteralText } from "../parser/tokens.ts";

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);

function normalizeMethod(token: string): string {
	const upper = token.toUpperCase();
	if (HTTP_METHODS.has(upper)) return upper;
	return upper;
}

function parseWgetMethod(tokens: string[]): { method: string; complete: boolean } {
	let method = "GET";
	let explicitMethod = false;

	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		const upper = token.toUpperCase();

		if (upper === "--METHOD") {
			if (i + 1 >= tokens.length) return { method: "GET", complete: false };
			const methodToken = tokens[i + 1].trim();
			if (!methodToken || methodToken.startsWith("-")) return { method: "GET", complete: false };
			method = normalizeMethod(methodToken);
			explicitMethod = true;
			i++;
			continue;
		}
		if (upper.startsWith("--METHOD=")) {
			const methodToken = token.slice("--method=".length).trim();
			if (!methodToken || methodToken.startsWith("-")) return { method: "GET", complete: false };
			method = normalizeMethod(methodToken);
			explicitMethod = true;
			continue;
		}

		const bodyNeedsValue = upper === "--POST-DATA" || upper === "--POST-FILE" || upper === "--BODY-DATA" || upper === "--BODY-FILE";
		if (bodyNeedsValue) {
			if (!explicitMethod) method = "POST";
			if (i + 1 >= tokens.length) return { method: "GET", complete: false };
			i++;
			continue;
		}
		if (
			upper.startsWith("--POST-DATA=") ||
			upper.startsWith("--POST-FILE=") ||
			upper.startsWith("--BODY-DATA=") ||
			upper.startsWith("--BODY-FILE=")
		) {
			if (!explicitMethod) method = "POST";
		}
	}

	return { method, complete: true };
}

export function extractWgetMethodPatterns(args: string[]): { patterns: string[]; complete: boolean } {
	const tokens: string[] = [];
	for (const raw of args) {
		const token = decodeLiteralText(raw) ?? raw.trim();
		if (!token) continue;
		tokens.push(token);
	}

	const parsed = parseWgetMethod(tokens);
	if (!parsed.complete) return { patterns: [], complete: false };
	return { patterns: [`wget ${parsed.method} *`], complete: true };
}
