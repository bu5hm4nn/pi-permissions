import { decodeLiteralText, normalizeExecutableToken, normalizeLiteralToken } from "../parser/tokens.ts";

const SHELL_EXECUTABLES = new Set(["sh", "bash", "ash", "dash", "zsh"]);

function splitDockerRunCommandArgs(args: string[]): { commandArgs: string[]; complete: boolean } {
	const longNeedsValue = new Set([
		"--add-host",
		"--blkio-weight",
		"--cap-add",
		"--cap-drop",
		"--cgroup-parent",
		"--cpus",
		"--cpu-shares",
		"--entrypoint",
		"--env",
		"--env-file",
		"--hostname",
		"--label",
		"--memory",
		"--mount",
		"--name",
		"--network",
		"--platform",
		"--publish",
		"--restart",
		"--runtime",
		"--tmpfs",
		"--ulimit",
		"--user",
		"--volume",
		"--workdir",
	]);
	const shortNeedsValue = new Set(["-e", "-h", "-l", "-m", "-p", "-u", "-v", "-w"]);

	let i = 0;
	let consumedImage = false;
	while (i < args.length) {
		const token = normalizeLiteralToken(args[i]);
		if (!token) return { commandArgs: [], complete: false };
		if (token === "--") {
			i++;
			break;
		}
		if (!token.startsWith("-")) {
			i++;
			consumedImage = true;
			break;
		}
		if (token.startsWith("--")) {
			if (token.includes("=")) {
				i++;
				continue;
			}
			if (longNeedsValue.has(token)) {
				if (i + 1 >= args.length) return { commandArgs: [], complete: false };
				i += 2;
				continue;
			}
			i++;
			continue;
		}
		if (shortNeedsValue.has(token)) {
			if (i + 1 >= args.length) return { commandArgs: [], complete: false };
			i += 2;
			continue;
		}
		i++;
	}

	if (!consumedImage) {
		if (i >= args.length) return { commandArgs: [], complete: false };
		i++;
	}

	return { commandArgs: args.slice(i), complete: true };
}

function splitDockerExecCommandArgs(args: string[]): { commandArgs: string[]; complete: boolean } {
	const longNeedsValue = new Set(["--detach-keys", "--env", "--env-file", "--user", "--workdir"]);
	const shortNeedsValue = new Set(["-e", "-u", "-w"]);

	let i = 0;
	let consumedContainer = false;
	while (i < args.length) {
		const token = normalizeLiteralToken(args[i]);
		if (!token) return { commandArgs: [], complete: false };
		if (token === "--") {
			i++;
			break;
		}
		if (!token.startsWith("-")) {
			i++;
			consumedContainer = true;
			break;
		}
		if (token.startsWith("--")) {
			if (token.includes("=")) {
				i++;
				continue;
			}
			if (longNeedsValue.has(token)) {
				if (i + 1 >= args.length) return { commandArgs: [], complete: false };
				i += 2;
				continue;
			}
			i++;
			continue;
		}
		if (shortNeedsValue.has(token)) {
			if (i + 1 >= args.length) return { commandArgs: [], complete: false };
			i += 2;
			continue;
		}
		i++;
	}

	if (!consumedContainer) {
		if (i >= args.length) return { commandArgs: [], complete: false };
		i++;
	}

	return { commandArgs: args.slice(i), complete: true };
}

function extractNestedShellOrCommandPatterns(
	commandArgs: string[],
	analyzeNested: (command: string) => { patterns: string[]; complete: boolean },
): { patterns: string[]; complete: boolean } {
	if (commandArgs.length === 0) return { patterns: [], complete: true };

	const firstToken = normalizeLiteralToken(commandArgs[0]);
	if (!firstToken) return { patterns: [], complete: false };
	const firstName = normalizeExecutableToken(firstToken);
	if (!firstName) return { patterns: [], complete: false };

	if (SHELL_EXECUTABLES.has(firstName)) {
		for (let j = 1; j < commandArgs.length; j++) {
			const opt = normalizeLiteralToken(commandArgs[j]);
			if (!opt) return { patterns: [], complete: false };
			if (opt === "--") continue;
			if (/^-[^-]*c[^-]*$/.test(opt) || opt === "--command") {
				if (j + 1 >= commandArgs.length) return { patterns: [], complete: false };
				const payload = decodeLiteralText(commandArgs[j + 1]);
				if (!payload) return { patterns: [], complete: false };
				return analyzeNested(payload);
			}
			if (opt.startsWith("-")) continue;
			break;
		}
		return { patterns: [], complete: true };
	}

	const joined = commandArgs.map((t) => decodeLiteralText(t) || t).join(" ");
	return analyzeNested(joined);
}

export function extractDockerShellPatterns(
	args: string[],
	subcommand: string,
	_depth: number,
	analyzeNested: (command: string) => { patterns: string[]; complete: boolean },
): { patterns: string[]; complete: boolean } {
	if (subcommand === "run") {
		const split = splitDockerRunCommandArgs(args);
		if (!split.complete) return { patterns: [], complete: false };
		return extractNestedShellOrCommandPatterns(split.commandArgs, analyzeNested);
	}
	if (subcommand === "exec") {
		const split = splitDockerExecCommandArgs(args);
		if (!split.complete) return { patterns: [], complete: false };
		return extractNestedShellOrCommandPatterns(split.commandArgs, analyzeNested);
	}
	return { patterns: [], complete: true };
}
