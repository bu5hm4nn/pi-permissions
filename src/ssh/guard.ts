import { analyzeCommandPatterns } from "../policy/command-patterns.ts";
import { buildCommandPreview, computeBashFingerprint } from "../policy/fingerprint.ts";
import { isDirectSshFamilyCommandDetailed, type SshCheckResult } from "../shell/analyzers/direct-ssh.ts";

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
	matchDirectSsh: (command: string) => boolean | SshCheckResult;
	audit?: (entry: Record<string, unknown>) => Promise<void>;
	// Optional bash permissions config
	bashPermissions?: { enabled: boolean };
	// Optional callback to check bash command approval
	checkBashApproval?: (fingerprint: string, domain: string, patterns?: string[], analysisComplete?: boolean) => Promise<BashApprovalResult>;
	// Whether UI is available for prompts
	hasUI?: boolean;
}

/**
 * Get a user-facing message for SSH block reasons.
 */
function getSshBlockMessage(reason: "ssh_detected" | "parse_failure" | "uncertain"): string {
	switch (reason) {
		case "ssh_detected":
			return "Direct SSH-family commands are blocked. Use ssh_bash.";
		case "parse_failure":
			return "Cannot safely parse command. Use ssh_bash for remote SSH.";
		case "uncertain":
			return "Command contains uncertain constructs. Use ssh_bash for remote SSH.";
	}
}

export async function handleToolCallGuard(event: any, runtime: GuardRuntime) {
	if (!runtime.guardHealthy) {
		if (event.toolName === "bash") return { block: true, reason: "SSH guard unhealthy: emergency fail-closed mode" };
		return;
	}
	if (event.toolName !== "bash") return;
	const cmd = String((event.input as any)?.command ?? "");

	// Always check direct SSH blocking first (takes precedence)
	let directSshResult: SshCheckResult = { blocked: true, reason: "parse_failure" };
	try {
		const result = runtime.matchDirectSsh(cmd);
		// Handle both boolean and detailed result formats
		if (typeof result === "boolean") {
			directSshResult = { blocked: result, reason: result ? undefined : undefined };
		} else {
			directSshResult = result;
		}
	} catch {
		// Matcher exception - fail-closed with generic SSH block message
		await runtime.audit?.({ event: "tool_call_block", reason: "direct_ssh_block", commandPreview: buildCommandPreview(cmd) });
		return { block: true, reason: "Direct SSH-family commands are blocked. Use ssh_bash." };
	}

	if (directSshResult.blocked) {
		// Determine reason: use detailed reason if available, otherwise default
		const reason = directSshResult.reason ?? "ssh_detected";
		const message = getSshBlockMessage(reason as "ssh_detected" | "parse_failure" | "uncertain");
		await runtime.audit?.({ event: "tool_call_block", reason: "direct_ssh_block", sshReason: reason, commandPreview: buildCommandPreview(cmd) });
		return { block: true, reason: message };
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

	// Check direct SSH blocking with detailed results
	let directSshResult: SshCheckResult = { blocked: true, reason: "parse_failure" };
	try {
		const result = runtime.matchDirectSsh(event.command);
		// Handle both boolean and detailed result formats
		if (typeof result === "boolean") {
			directSshResult = { blocked: result, reason: result ? undefined : undefined };
		} else {
			directSshResult = result;
		}
	} catch {
		// Matcher exception - fail-closed with generic SSH block message
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

	if (!directSshResult.blocked) return;

	const reason = directSshResult.reason ?? "ssh_detected";
	let message: string;
	switch (reason) {
		case "ssh_detected":
			message = "Blocked: Direct SSH-family commands are disabled. Use ssh_bash.";
			break;
		case "parse_failure":
			message = "Blocked: Cannot safely parse command. Use ssh_bash for remote SSH.";
			break;
		case "uncertain":
			message = "Blocked: Command contains uncertain constructs. Use ssh_bash for remote SSH.";
			break;
		default:
			message = "Blocked: Direct SSH-family commands are disabled. Use ssh_bash.";
	}

	await runtime.audit?.({ event: "user_bash_block", reason: "direct_ssh_block", sshReason: reason, commandPreview: buildCommandPreview(event.command) });
	return {
		result: {
			output: message,
			exitCode: 126,
			cancelled: false,
			truncated: false,
		},
	};
}
