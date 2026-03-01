import { buildCommandPreview } from "../policy/fingerprint.ts";

export interface GuardRuntime {
	guardHealthy: boolean;
	matchDirectSsh: (command: string) => boolean;
	audit?: (entry: Record<string, unknown>) => Promise<void>;
}

export async function handleToolCallGuard(event: any, runtime: GuardRuntime) {
	if (!runtime.guardHealthy) {
		if (event.toolName === "bash") return { block: true, reason: "SSH guard unhealthy: emergency fail-closed mode" };
		return;
	}
	if (event.toolName !== "bash") return;
	const cmd = String((event.input as any)?.command ?? "");
	let blocked = true;
	try {
		blocked = runtime.matchDirectSsh(cmd);
	} catch {
		blocked = true;
	}
	if (!blocked) return;
	await runtime.audit?.({ event: "tool_call_block", reason: "direct_ssh_block", commandPreview: buildCommandPreview(cmd) });
	return { block: true, reason: "Direct SSH-family commands are blocked. Use ssh_bash." };
}

export async function handleUserBashGuard(event: { command: string }, runtime: GuardRuntime) {
	if (!runtime.guardHealthy) {
		return {
			result: {
				output: "Blocked: SSH guard unhealthy (emergency fail-closed mode).",
				exitCode: 126,
				cancelled: false,
				truncated: false,
			},
		};
	}
	let blocked = true;
	try {
		blocked = runtime.matchDirectSsh(event.command);
	} catch {
		blocked = true;
	}
	if (!blocked) return;
	await runtime.audit?.({ event: "user_bash_block", reason: "direct_ssh_block", commandPreview: buildCommandPreview(event.command) });
	return {
		result: {
			output: "Blocked: direct SSH-family commands are disabled. Use ssh_bash tool.",
			exitCode: 126,
			cancelled: false,
			truncated: false,
		},
	};
}
