import { analyzeCommandPatterns } from "../policy/command-patterns.ts";
import { buildCommandPreview, computeBashFingerprint } from "../policy/fingerprint.ts";

export interface BashApprovalResult {
	approved: boolean;
	scope: "none" | "session" | "project" | "global";
}

export interface GuardResult {
	block?: boolean;
	reason?: string;
	promptNeeded?: boolean;
	fingerprint?: string;
	patterns?: string[];
	commandPreview?: string;
	patternAnalysisComplete?: boolean;
}

export interface GuardRuntime {
	guardHealthy: boolean;
	matchDirectSsh: (command: string) => boolean;
	audit?: (entry: Record<string, unknown>) => Promise<void>;
	// Optional bash permissions config
	bashPermissions?: { enabled: boolean };
	// Optional callback to check bash command approval
	checkBashApproval?: (fingerprint: string, domain: string, patterns?: string[], analysisComplete?: boolean) => Promise<BashApprovalResult>;
	// Whether UI is available for prompts
	hasUI?: boolean;
}

export async function handleToolCallGuard(event: any, runtime: GuardRuntime) {
	if (!runtime.guardHealthy) {
		if (event.toolName === "bash") return { block: true, reason: "SSH guard unhealthy: emergency fail-closed mode" };
		return;
	}
	if (event.toolName !== "bash") return;
	const cmd = String((event.input as any)?.command ?? "");

	// Always check direct SSH blocking first (takes precedence)
	let directSshBlocked = true;
	try {
		directSshBlocked = runtime.matchDirectSsh(cmd);
	} catch {
		directSshBlocked = true;
	}
	if (directSshBlocked) {
		await runtime.audit?.({ event: "tool_call_block", reason: "direct_ssh_block", commandPreview: buildCommandPreview(cmd) });
		return { block: true, reason: "Direct SSH-family commands are blocked. Use ssh_bash." };
	}

	// If bash permissions not enabled (default), passthrough
	if (!runtime.bashPermissions?.enabled) {
		return;
	}

	// Bash permissions enabled - check approval
	if (runtime.checkBashApproval) {
		const fingerprint = computeBashFingerprint(cmd);
		const patternAnalysis = analyzeCommandPatterns(cmd);
		const patterns = patternAnalysis.patterns;
		const commandPreview = buildCommandPreview(cmd);

		const approval = await runtime.checkBashApproval(fingerprint, "bash", patterns, patternAnalysis.complete);
		if (approval.approved) {
			if (!runtime.hasUI && approval.scope === "session") {
				await runtime.audit?.({
					event: "tool_call_block",
					reason: "bash_session_approved_no_ui",
					commandPreview,
					fingerprint,
					patterns,
				});
				return { block: true, reason: "Bash command not approved. Enable UI for approval prompts." };
			}
			return; // Passthrough
		}

		// Not approved - if UI available, signal prompt needed; otherwise block
		if (runtime.hasUI) {
			return {
				promptNeeded: true,
				fingerprint,
				patterns,
				commandPreview,
				patternAnalysisComplete: patternAnalysis.complete,
			};
		}

		// No UI - block with appropriate message
		await runtime.audit?.({
			event: "tool_call_block",
			reason: "bash_not_approved",
			commandPreview,
			fingerprint,
			patterns,
		});
		return { block: true, reason: "Bash command not approved. Enable UI for approval prompts." };
	}

	// No approval callback but bash permissions enabled - fail-closed (block regardless of UI)
	await runtime.audit?.({
		event: "tool_call_block",
		reason: "bash_no_approval_callback",
		commandPreview: buildCommandPreview(cmd),
	});
	return { block: true, reason: "Bash command not approved. Enable UI for approval prompts." };
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
