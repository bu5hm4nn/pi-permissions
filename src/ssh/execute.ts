import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createWriteStream } from "node:fs";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TextContent } from "@mariozechner/pi-ai";
import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, formatSize, truncateTail } from "@mariozechner/pi-coding-agent";

export interface SshExecParams {
	target: string;
	command: string;
	cwd?: string;
	timeout?: number;
	signal?: AbortSignal;
	onChunk?: (chunk: string) => void;
}

export interface SshExecResult {
	text: string;
	exitCode: number | undefined;
	truncated: boolean;
	fullOutputPath?: string;
	timedOut: boolean;
	aborted: boolean;
}

function q(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

function buildRemoteCommand(command: string, cwd?: string): string {
	if (!cwd) return `bash -lc ${q(command)}`;
	return `bash -lc ${q(`cd ${q(cwd)} && ${command}`)}`;
}

function tempLogPath(): string {
	return join(tmpdir(), `pi-ssh-${randomBytes(8).toString("hex")}.log`);
}

async function closeTempStream(stream: ReturnType<typeof createWriteStream>): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		stream.once("finish", () => resolve());
		stream.once("error", (err) => reject(err));
		stream.end();
	});
}

export async function executeSsh(params: SshExecParams): Promise<SshExecResult> {
	const sshArgs = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", params.target, buildRemoteCommand(params.command, params.cwd)];
	const child = spawn("ssh", sshArgs, { stdio: ["ignore", "pipe", "pipe"] });

	const chunks: Buffer[] = [];
	let bytes = 0;
	let tempPath: string | undefined;
	let tempStream: ReturnType<typeof createWriteStream> | undefined;
	let timeoutHandle: NodeJS.Timeout | undefined;
	let timedOut = false;
	let aborted = false;

	const onData = (buf: Buffer) => {
		chunks.push(buf);
		bytes += buf.length;
		if (bytes > DEFAULT_MAX_BYTES && !tempPath) {
			tempPath = tempLogPath();
			tempStream = createWriteStream(tempPath, { encoding: "utf-8" });
			for (let i = 0; i < chunks.length - 1; i++) tempStream.write(chunks[i]);
		}
		if (tempStream) tempStream.write(buf);
		params.onChunk?.(buf.toString("utf-8"));
	};

	child.stdout?.on("data", onData);
	child.stderr?.on("data", onData);

	if (params.timeout && params.timeout > 0) {
		timeoutHandle = setTimeout(() => {
			timedOut = true;
			child.kill("SIGKILL");
		}, params.timeout * 1000);
	}

	const onAbort = () => {
		aborted = true;
		child.kill("SIGKILL");
	};
	params.signal?.addEventListener("abort", onAbort, { once: true });
	if (params.signal?.aborted) {
		onAbort();
	}

	const exitCode = await new Promise<number | undefined>((resolve) => {
		child.on("close", (code) => resolve(code === null ? undefined : code));
		child.on("error", () => resolve(1));
	});

	if (timeoutHandle) clearTimeout(timeoutHandle);
	params.signal?.removeEventListener("abort", onAbort);
	if (tempStream) {
		await closeTempStream(tempStream);
	}

	const output = Buffer.concat(chunks).toString("utf-8");
	const trunc = truncateTail(output, { maxBytes: DEFAULT_MAX_BYTES, maxLines: DEFAULT_MAX_LINES });
	if (trunc.truncated && !tempPath) {
		tempPath = tempLogPath();
		await writeFile(tempPath, output, "utf-8");
	}

	let text = trunc.content || "(no output)";
	if (trunc.truncated && tempPath) {
		const startLine = trunc.totalLines - trunc.outputLines + 1;
		const endLine = trunc.totalLines;
		text += `\n\n[Showing lines ${startLine}-${endLine} of ${trunc.totalLines} (${formatSize(DEFAULT_MAX_BYTES)} limit). Full output: ${tempPath}]`;
	}

	if (timedOut) {
		text += `\n\nCommand timed out after ${params.timeout} seconds`;
		return {
			text,
			exitCode: undefined,
			truncated: trunc.truncated,
			fullOutputPath: trunc.truncated ? tempPath : undefined,
			timedOut: true,
			aborted,
		};
	}
	if (aborted || params.signal?.aborted) {
		text += "\n\nCommand aborted";
		return {
			text,
			exitCode: undefined,
			truncated: trunc.truncated,
			fullOutputPath: trunc.truncated ? tempPath : undefined,
			timedOut: false,
			aborted: true,
		};
	}
	return {
		text,
		exitCode,
		truncated: trunc.truncated,
		fullOutputPath: trunc.truncated ? tempPath : undefined,
		timedOut: false,
		aborted: false,
	};
}

export function toToolContent(text: string): TextContent[] {
	return [{ type: "text", text }];
}
