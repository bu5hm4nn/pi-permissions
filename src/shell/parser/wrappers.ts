import { isEnvAssignmentToken } from "./tokens.ts";

export const STANDARD_WRAPPERS = new Set(["sudo", "env", "command", "builtin", "exec", "nohup", "time", "nice"]);
export const SSH_MATCHER_WRAPPERS = new Set([...STANDARD_WRAPPERS, "coproc"]);

function stepSudo(tokens: string[], start: number): number | null {
	const noArg = new Set(["-A", "-b", "-E", "-e", "-H", "-K", "-k", "-n", "-S", "-V", "-v", "-l"]);
	const needsArg = new Set(["-C", "-g", "-h", "-p", "-R", "-r", "-t", "-u", "-U", "-T"]);
	const longNoArg = new Set([
		"--askpass",
		"--background",
		"--edit",
		"--help",
		"--non-interactive",
		"--preserve-env",
		"--remove-timestamp",
		"--reset-timestamp",
		"--set-home",
		"--stdin",
		"--validate",
		"--version",
	]);
	const longNeedsArg = new Set([
		"--chdir",
		"--close-from",
		"--group",
		"--host",
		"--other-user",
		"--prompt",
		"--role",
		"--type",
		"--user",
	]);

	let i = start;
	while (i < tokens.length) {
		const t = tokens[i];
		if (t === "--") {
			i++;
			break;
		}
		if (!t.startsWith("-")) break;
		if (t.startsWith("--")) {
			const [name, inlineValue] = t.split("=", 2);
			if (longNoArg.has(name)) {
				i++;
				continue;
			}
			if (longNeedsArg.has(name)) {
				if (inlineValue !== undefined) {
					i++;
					continue;
				}
				if (i + 1 >= tokens.length) return null;
				i += 2;
				continue;
			}
			return null;
		}
		if (noArg.has(t)) {
			i++;
			continue;
		}
		if (needsArg.has(t)) {
			if (i + 1 >= tokens.length) return null;
			i += 2;
			continue;
		}
		return null;
	}

	while (i < tokens.length && isEnvAssignmentToken(tokens[i])) i++;
	return i < tokens.length ? i : null;
}

function stepEnv(tokens: string[], start: number): number | null {
	let i = start;
	while (i < tokens.length) {
		const t = tokens[i];
		if (t === "--") return i + 1;
		if (isEnvAssignmentToken(t)) {
			i++;
			continue;
		}
		if (!t.startsWith("-")) break;
		if (t === "-i" || t === "-0" || t === "--ignore-environment" || t === "--null") {
			i++;
			continue;
		}
		if (t === "-u" || t === "-C" || t === "--unset" || t === "--chdir") {
			if (i + 1 >= tokens.length) return null;
			i += 2;
			continue;
		}
		if (t.startsWith("--unset=") || t.startsWith("--chdir=")) {
			i++;
			continue;
		}
		return null;
	}
	return i;
}

function stepCommand(tokens: string[], start: number): number | null {
	let i = start;
	while (i < tokens.length) {
		const t = tokens[i];
		if (t === "--") return i + 1;
		if (!t.startsWith("-")) break;
		if (/^-[pVv]+$/.test(t)) {
			i++;
			continue;
		}
		return null;
	}
	return i;
}

function stepTime(tokens: string[], start: number): number | null {
	let i = start;
	while (i < tokens.length) {
		const t = tokens[i];
		if (t === "--") return i + 1;
		if (!t.startsWith("-")) break;
		if (t === "-p" || t === "-a" || t === "-v" || t === "--portability") {
			i++;
			continue;
		}
		if (t === "-f" || t === "-o" || t === "--format" || t === "--output") {
			if (i + 1 >= tokens.length) return null;
			i += 2;
			continue;
		}
		if (t.startsWith("--format=") || t.startsWith("--output=")) {
			i++;
			continue;
		}
		return null;
	}
	return i;
}

function stepNice(tokens: string[], start: number): number | null {
	let i = start;
	while (i < tokens.length) {
		const t = tokens[i];
		if (t === "--") return i + 1;
		if (!t.startsWith("-")) break;
		if (t === "-n" || t === "--adjustment") {
			if (i + 1 >= tokens.length) return null;
			i += 2;
			continue;
		}
		if (t.startsWith("--adjustment=") || /^-[0-9]+$/.test(t)) {
			i++;
			continue;
		}
		return null;
	}
	return i;
}

export function stepWrapper(wrapper: string, tokens: string[], i: number): number | null {
	if (wrapper === "sudo") return stepSudo(tokens, i);
	if (wrapper === "env") return stepEnv(tokens, i);
	if (wrapper === "command") return stepCommand(tokens, i);
	if (wrapper === "time") return stepTime(tokens, i);
	if (wrapper === "nice") return stepNice(tokens, i);

	if (wrapper === "exec" || wrapper === "builtin" || wrapper === "nohup") {
		if (i >= tokens.length) return null;
		if (tokens[i] === "--") return i + 1;
		if (tokens[i].startsWith("-")) return null;
		return i;
	}
	if (wrapper === "coproc") {
		if (i >= tokens.length) return null;
		if (tokens[i] === "--") return i + 1;
		if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(tokens[i]) && i + 1 < tokens.length) i++;
		if (tokens[i].startsWith("-")) return null;
		return i;
	}
	return null;
}
