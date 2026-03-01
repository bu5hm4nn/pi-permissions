import { decodeLiteralText, normalizeExecutableToken } from "../parser/tokens.ts";

const CURL_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);
const URL_SCOPED_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function methodFromCurlToken(token: string): string {
	const upper = token.toUpperCase();
	if (CURL_METHODS.has(upper)) return upper;
	return upper;
}

function parseCurlTransferMethod(tokens: string[]): { method: string; complete: boolean } {
	let method = "GET";
	let explicitMethod = false;
	let forceGet = false;

	const parseExplicitMethod = (value: string): string | null => {
		const trimmed = value.trim();
		if (!trimmed || trimmed.startsWith("-")) return null;
		return methodFromCurlToken(trimmed);
	};

	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		const upper = token.toUpperCase();

		if (token === "-X" || upper === "--REQUEST") {
			if (i + 1 >= tokens.length) return { method: "GET", complete: false };
			const parsedMethod = parseExplicitMethod(tokens[i + 1]);
			if (!parsedMethod) return { method: "GET", complete: false };
			method = parsedMethod;
			explicitMethod = true;
			i++;
			continue;
		}
		if (/^-X.+/.test(token)) {
			const parsedMethod = parseExplicitMethod(token.slice(2));
			if (!parsedMethod) return { method: "GET", complete: false };
			method = parsedMethod;
			explicitMethod = true;
			continue;
		}
		if (upper.startsWith("--REQUEST=")) {
			const parsedMethod = parseExplicitMethod(token.slice("--request=".length));
			if (!parsedMethod) return { method: "GET", complete: false };
			method = parsedMethod;
			explicitMethod = true;
			continue;
		}

		if (token === "-G" || upper === "--GET") {
			forceGet = true;
			if (!explicitMethod) method = "GET";
			continue;
		}
		if (token === "-I" || upper === "--HEAD") {
			if (!explicitMethod && !forceGet) method = "HEAD";
			continue;
		}

		const dataNeedsValue =
			token === "-d" ||
			upper === "--DATA" ||
			upper === "--DATA-RAW" ||
			upper === "--DATA-BINARY" ||
			upper === "--DATA-URLENCODE" ||
			token === "-F" ||
			upper === "--FORM" ||
			upper === "--FORM-STRING" ||
			upper === "--JSON";
		if (dataNeedsValue) {
			if (!explicitMethod && !forceGet) method = "POST";
			if (i + 1 >= tokens.length) return { method: "GET", complete: false };
			i++;
			continue;
		}
		if (/^-d.+/.test(token) || /^-F.+/.test(token)) {
			if (!explicitMethod && !forceGet) method = "POST";
			continue;
		}
		if (
			upper.startsWith("--DATA=") ||
			upper.startsWith("--DATA-RAW=") ||
			upper.startsWith("--DATA-BINARY=") ||
			upper.startsWith("--DATA-URLENCODE=") ||
			upper.startsWith("--FORM=") ||
			upper.startsWith("--FORM-STRING=") ||
			upper.startsWith("--JSON=")
		) {
			if (!explicitMethod && !forceGet) method = "POST";
			continue;
		}

		const uploadNeedsValue = token === "-T" || upper === "--UPLOAD-FILE";
		if (uploadNeedsValue) {
			if (!explicitMethod && !forceGet) method = "PUT";
			if (i + 1 >= tokens.length) return { method: "GET", complete: false };
			i++;
			continue;
		}
		if (/^-T.+/.test(token) || upper.startsWith("--UPLOAD-FILE=")) {
			if (!explicitMethod && !forceGet) method = "PUT";
			continue;
		}
	}

	return { method, complete: true };
}

function extractCurlTransferUrl(tokens: string[]): string | null {
	for (let i = tokens.length - 1; i >= 0; i--) {
		const token = tokens[i].trim();
		if (!token || token.startsWith("-")) continue;
		if (/^[a-z][a-z0-9+.-]*:\/\//i.test(token)) return token;
	}
	return null;
}

function canonicalizeTransferUrl(rawUrl: string): string | null {
	try {
		const url = new URL(rawUrl);
		if (!url.protocol || !url.hostname) return null;
		const protocol = url.protocol.toLowerCase();
		const hostname = url.hostname.toLowerCase();
		const omitPort = (protocol === "http:" && url.port === "80") || (protocol === "https:" && url.port === "443");
		const port = url.port && !omitPort ? `:${url.port}` : "";
		const path = url.pathname || "/";
		return `${protocol}//${hostname}${port}${path}`;
	} catch {
		return null;
	}
}

export function extractCurlMethodPatterns(args: string[]): { patterns: string[]; complete: boolean } {
	const segments: string[][] = [[]];
	for (const raw of args) {
		const token = decodeLiteralText(raw) ?? raw.trim();
		if (!token) continue;
		if (token === "--next" || token === "-:") {
			segments.push([]);
			continue;
		}
		segments[segments.length - 1].push(token);
	}

	const patterns: string[] = [];
	for (const segment of segments) {
		if (segment.length === 0) continue;
		const first = normalizeExecutableToken(segment[0]);
		const transfer = first === "curl" ? segment.slice(1) : segment;
		const parsed = parseCurlTransferMethod(transfer);
		if (!parsed.complete) return { patterns: [], complete: false };
		const transferUrl = extractCurlTransferUrl(transfer);
		const scope =
			URL_SCOPED_METHODS.has(parsed.method) && transferUrl
				? (canonicalizeTransferUrl(transferUrl) ?? transferUrl)
				: "*";
		patterns.push(`curl ${parsed.method} ${scope}`);
	}

	if (patterns.length === 0) return { patterns: ["curl GET *"], complete: true };
	return { patterns, complete: true };
}
