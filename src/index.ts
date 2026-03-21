import { constants as fsConstants, existsSync } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { registerPolicyCommands } from "./commands/ssh-policy.ts";
import { analyzeCommandPatterns, formatAllowPatternSummary, getFallbackPattern } from "./policy/command-patterns.ts";
import { isBashSessionApproved } from "./policy/bash-session-approval.ts";
import { buildCommandPreview, computeBashFingerprint, computeFingerprint, isReusableUnsafe } from "./policy/fingerprint.ts";
import { initAnalysisLog, logAnalysisResult } from "./policy/analysis-log.ts";
import type { PolicyFile } from "./policy/schema.ts";
import { emptyPolicyFile } from "./policy/schema.ts";
import {
	readPermissionsConfig,
	readPolicy,
	removeGrantByPrefix,
	resolveStorePaths,
	type StorePaths,
	type PermissionsConfigResult,
	upsertGrant,
	writePolicy,
} from "./policy/store.ts";
import { isProjectTrusted, trustProject } from "./policy/trust.ts";
import { executeSsh, toToolContent } from "./ssh/execute.ts";
import { handleToolCallGuard, handleUserBashGuard } from "./ssh/guard.ts";
import { isDirectSshFamilyCommand, isDirectSshFamilyCommandDetailed } from "./ssh/matcher.ts";
import { validateSshInput } from "./ssh/validate.ts";
import { promptPermission, type PermissionDecision } from "./ui/prompt.ts";

const schema = Type.Object({
	target: Type.String({ description: "SSH target, e.g. user@host" }),
	command: Type.String({ description: "Remote bash command" }),
	cwd: Type.Optional(Type.String({ description: "Remote working directory (optional)" })),
	timeout: Type.Optional(Type.Number({ description: "Timeout in seconds" })),
});

function now() {
	return new Date().toISOString();
}

export interface SshPermissionExtensionOptions {
	directSshMatcher?: (command: string) => boolean | { blocked: boolean; reason?: "ssh_detected" | "parse_failure" | "uncertain" };
}

export default function sshPermissionExtension(pi: ExtensionAPI, options?: SshPermissionExtensionOptions) {
	// Use detailed matcher internally, wrapping boolean matchers to match interface
	const directSshMatcher = options?.directSshMatcher ?? isDirectSshFamilyCommand;
	let paths: StorePaths | null = null;
	let sessionGrants = new Set<string>();
	let bashSessionGrants = new Set<string>();
	let guardHealthy = true;
	let permissionsConfig: PermissionsConfigResult = { ssh: { enabled: true }, bash: { enabled: false } };

	const auditPath = join(process.env.HOME || "", ".pi", "agent", "ssh-policy-audit.log");

	async function appendAuditLine(line: string) {
		await mkdir(dirname(auditPath), { recursive: true, mode: 0o700 });

		try {
			const lst = await lstat(auditPath);
			if (lst.isSymbolicLink()) {
				throw new Error(`Audit log symlink path is not allowed: ${auditPath}`);
			}
		} catch (e) {
			if ((e as { code?: string }).code !== "ENOENT") throw e;
		}

		const noFollow = (fsConstants as any).O_NOFOLLOW ?? 0;
		const flags = fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_WRONLY | noFollow;
		const handle = await open(auditPath, flags, 0o600);
		try {
			const s = await handle.stat();
			if (!s.isFile()) throw new Error(`Audit log path is not a regular file: ${auditPath}`);
			if ((s.mode & 0o022) !== 0) throw new Error(`Insecure audit log permissions: ${auditPath}`);
			if (typeof process.getuid === "function" && s.uid !== process.getuid()) {
				throw new Error(`Audit log owner mismatch: ${auditPath}`);
			}
			await handle.writeFile(line, { encoding: "utf-8" });
		} finally {
			await handle.close();
		}
	}

	async function audit(entry: Record<string, unknown>) {
		try {
			await appendAuditLine(`${JSON.stringify({ timestamp: now(), ...entry })}\n`);
		} catch {
			// ignore audit write failures
		}
	}

	function requirePaths() {
		if (!paths) throw new Error("SSH policy paths not initialized");
		return paths;
	}

	async function runStartupSelfCheck(cwd: string) {
		const resolved = resolveStorePaths(cwd);
		await readPolicy(resolved.globalPath);
		const trustedProject = await isProjectTrusted(resolved.projectId);
		if (trustedProject) await readPolicy(resolved.projectPath);

		// Self-check cases: command, expected blocked, and optional expected reason
		const matcherCases: Array<{ command: string; expectedBlocked: boolean; expectedReason?: "ssh_detected" | "parse_failure" | "uncertain" }> = [
			{ command: "echo ok", expectedBlocked: false },
			{ command: "FOO=bar", expectedBlocked: false },
			{ command: "echo hi > out.txt", expectedBlocked: false },
			{ command: "ssh user@host", expectedBlocked: true, expectedReason: "ssh_detected" },
			{ command: "\\ssh user@host", expectedBlocked: true, expectedReason: "ssh_detected" },
			{ command: "sudo -- ssh user@host", expectedBlocked: true, expectedReason: "ssh_detected" },
			{ command: "\\sudo -- \\ssh user@host", expectedBlocked: true, expectedReason: "ssh_detected" },
			// Parse failures are fail-closed and should be blocked with parse_failure reason
			{ command: "echo 'unterminated", expectedBlocked: true, expectedReason: "parse_failure" },
			{ command: "echo ok &&", expectedBlocked: true, expectedReason: "parse_failure" },
		];

		// Use detailed matcher for self-check to verify both blocked status and reason
		const detailedMatcher = isDirectSshFamilyCommandDetailed;
		for (const c of matcherCases) {
			let result: { blocked: boolean; reason?: string };
			try {
				result = detailedMatcher(c.command);
			} catch {
				result = { blocked: true, reason: "parse_failure" };
			}
			if (result.blocked !== c.expectedBlocked) {
				throw new Error(`matcher self-check failed for command '${c.command}': blocked=${result.blocked}, expected blocked=${c.expectedBlocked}`);
			}
			// Verify reason for blocked cases that have expected reason
			if (c.expectedBlocked && c.expectedReason !== undefined) {
				if (result.reason !== c.expectedReason) {
					throw new Error(`matcher self-check failed for command '${c.command}': reason='${result.reason}', expected reason='${c.expectedReason}'`);
				}
			}
		}

		return resolved;
	}

	async function readGlobalPolicy(): Promise<PolicyFile> {
		return readPolicy(requirePaths().globalPath);
	}

	async function readProjectPolicy(): Promise<PolicyFile> {
		const p = requirePaths();
		if (existsSync(p.projectPath)) {
			return readPolicy(p.projectPath);
		}
		const legacy = await readPolicy(p.legacyProjectPath);
		if (legacy.grants.length > 0) {
			await writePolicy(p.projectPath, legacy);
		}
		return legacy;
	}

	async function writeGlobalPolicy(policy: PolicyFile) {
		await writePolicy(requirePaths().globalPath, policy);
	}

	async function writeProjectPolicy(policy: PolicyFile) {
		await writePolicy(requirePaths().projectPath, policy);
	}

	function revokeSessionByPrefix(prefix: string): { ok: boolean; message: string } {
		const matches = Array.from(sessionGrants).filter((fp) => fp.startsWith(prefix));
		if (matches.length === 0) return { ok: false, message: "No matching fingerprint" };
		if (matches.length > 1) return { ok: false, message: "Ambiguous prefix, provide more characters" };
		sessionGrants.delete(matches[0]);
		return { ok: true, message: `Revoked ${matches[0].slice(0, 12)}… from session` };
	}

	async function revokeByPrefix(scope: "global" | "project", prefix: string) {
		if (!/^[0-9a-fA-F]{8,}$/.test(prefix)) {
			return { ok: false, message: "Prefix must be hex and at least 8 chars" };
		}
		const current = scope === "global" ? await readGlobalPolicy() : await readProjectPolicy();
		const { policy, matches } = removeGrantByPrefix(current, prefix.toLowerCase());
		if (matches.length === 0) return { ok: false, message: "No matching fingerprint" };
		if (matches.length > 1) return { ok: false, message: "Ambiguous prefix, provide more characters" };
		if (scope === "global") await writeGlobalPolicy(policy);
		else await writeProjectPolicy(policy);
		return { ok: true, message: `Revoked ${matches[0].fingerprint.slice(0, 12)}… from ${scope}` };
	}

	async function getApprovalFromPolicies(
		exactFingerprint: string,
		reusableEntries: Array<{ fingerprint: string; pattern: string; fallbackFingerprint?: string }>,
		hasUI: boolean,
		analysisComplete: boolean = true,
	): Promise<{
		approved: boolean;
		scope: "none" | "session" | "project" | "global";
		policyError?: string;
		missingPatterns?: string[];
	}> {
		const isApprovedInSet = (entry: { fingerprint: string; fallbackFingerprint?: string }, set: Set<string>) =>
			set.has(entry.fingerprint) || (entry.fallbackFingerprint !== undefined && set.has(entry.fallbackFingerprint));

		const sessionApprovedExact = hasUI && sessionGrants.has(exactFingerprint);
		// Only use reusable patterns when analysis is complete
		const sessionApprovedReusableOnly =
			hasUI && analysisComplete && reusableEntries.length > 0 && reusableEntries.every((entry) => isApprovedInSet(entry, sessionGrants));
		try {
			const global = await readGlobalPolicy();
			const trustedProject = await isProjectTrusted(requirePaths().projectId);
			const project = trustedProject ? await readProjectPolicy() : emptyPolicyFile();
			const globalSet = new Set(global.grants.map((g) => g.fingerprint));
			const projectSet = new Set(project.grants.map((g) => g.fingerprint));
			const persistentEffective = new Set(globalSet);
			if (trustedProject) {
				for (const fp of projectSet) persistentEffective.add(fp);
			}
			const sessionEffective = new Set(sessionGrants);
			for (const fp of persistentEffective) sessionEffective.add(fp);

			// Only use reusable patterns when analysis is complete
			const reusableSatisfiedBySession =
				hasUI && analysisComplete && reusableEntries.length > 0 && reusableEntries.every((entry) => isApprovedInSet(entry, sessionEffective));
			const reusableSatisfiedByPersistent =
				analysisComplete && reusableEntries.length > 0 && reusableEntries.every((entry) => isApprovedInSet(entry, persistentEffective));

			if (sessionApprovedExact || reusableSatisfiedBySession) return { approved: true, scope: "session" };
			if (globalSet.has(exactFingerprint)) return { approved: true, scope: "global" };
			if (trustedProject && projectSet.has(exactFingerprint)) return { approved: true, scope: "project" };
			if (reusableSatisfiedByPersistent) {
				const hasProjectComponent = trustedProject && reusableEntries.some((entry) => isApprovedInSet(entry, projectSet));
				return { approved: true, scope: hasProjectComponent ? "project" : "global" };
			}
			const missingPatterns = reusableEntries
				.filter((entry) => !isApprovedInSet(entry, sessionEffective))
				.map((entry) => entry.pattern);
			return { approved: false, scope: "none", missingPatterns };
		} catch (e) {
			if (sessionApprovedExact || sessionApprovedReusableOnly) {
				return { approved: true, scope: "session", policyError: e instanceof Error ? e.message : String(e) };
			}
			return { approved: false, scope: "none", policyError: e instanceof Error ? e.message : String(e) };
		}
	}

	async function ensureProjectTrust(ctx: any): Promise<boolean> {
		const p = requirePaths();
		if (await isProjectTrusted(p.projectId)) return true;
		if (!ctx.hasUI) return false;
		const ok = await ctx.ui.confirm(
			"Trust project for SSH policy?",
			`Project: ${p.projectRootRealpath}\nStore: ${p.projectPath}\n\nAllow this project to persist ssh approvals?`,
		);
		if (!ok) return false;
		await trustProject(p.projectId, p.projectRootRealpath);
		return true;
	}

	registerPolicyCommands(pi, {
		getSessionFingerprints: () => sessionGrants,
		clearSession: () => {
			sessionGrants = new Set();
		},
		revokeSessionByPrefix,
		readGlobal: readGlobalPolicy,
		readProject: readProjectPolicy,
		isProjectTrusted: () => isProjectTrusted(requirePaths().projectId),
		writeGlobal: writeGlobalPolicy,
		writeProject: writeProjectPolicy,
		revokeGlobalByPrefix: (prefix) => revokeByPrefix("global", prefix),
		revokeProjectByPrefix: (prefix) => revokeByPrefix("project", prefix),
		reload: async () => {
			await readGlobalPolicy();
			const trustedProject = await isProjectTrusted(requirePaths().projectId);
			if (trustedProject) await readProjectPolicy();
		},
		// Live reload callback: reload permissions config from disk
		reloadPermissionsConfig: async () => {
			const cwd = paths?.projectRoot ?? process.cwd();
			permissionsConfig = await readPermissionsConfig(cwd);
			return permissionsConfig;
		},
		// Notification callback: called after config is reloaded
		onPermissionsConfigChanged: (newConfig) => {
			permissionsConfig = newConfig;
		},
	});

	pi.on("session_start", async (_event, ctx) => {
		sessionGrants = new Set();
		bashSessionGrants = new Set();
		try {
			paths = await runStartupSelfCheck(ctx.cwd);
			guardHealthy = true;
			// Initialize analysis log for commands that need pattern improvement
			initAnalysisLog(dirname(paths.globalPath));
			// Load permissions config
			try {
				permissionsConfig = await readPermissionsConfig(ctx.cwd);
			} catch {
				// Use defaults if config read fails
				permissionsConfig = { ssh: { enabled: true }, bash: { enabled: false } };
			}
			ctx.ui.setStatus("ssh-policy", ctx.ui.theme.fg("accent", "ssh-permission: active"));
		} catch (e) {
			guardHealthy = false;
			paths = null;
			permissionsConfig = { ssh: { enabled: true }, bash: { enabled: false } };
			ctx.ui.setStatus("ssh-policy", ctx.ui.theme.fg("error", "ssh-permission: fail-closed"));
			ctx.ui.notify(`ssh-permission startup self-check failed: ${e instanceof Error ? e.message : String(e)}`, "error");
		}
	});

	const clearSessionGrants = () => {
		sessionGrants = new Set();
		bashSessionGrants = new Set();
	};

	const clearSessionGrantsOnBoundary = (event?: { reason?: unknown }) => {
		const reason = typeof event?.reason === "string" ? event.reason : "unknown";
		if (reason === "resume") {
			// Explicitly clear grants for /resume.
			clearSessionGrants();
			return;
		}
		// Keep fail-closed behavior for all other boundary reasons.
		clearSessionGrants();
	};

	pi.on("session_before_switch", async (event: any) => {
		clearSessionGrantsOnBoundary(event);
	});

	pi.on("session_switch", async (event: any) => {
		clearSessionGrantsOnBoundary(event);
	});

	pi.on("session_fork", async (event: any) => {
		clearSessionGrantsOnBoundary(event);
	});

	pi.on("tool_call", async (event, ctx) => {
		const result = await handleToolCallGuard(event, {
			guardHealthy,
			matchDirectSsh: directSshMatcher,
			audit,
			bashPermissions: permissionsConfig.bash,
			hasUI: ctx?.hasUI ?? false,
			checkBashApproval: async (fingerprint, _domain, patterns, analysisComplete) => {
				const hasUI = ctx?.hasUI ?? false;
				if (
					hasUI &&
					isBashSessionApproved({ fingerprint, patterns, bashSessionGrants, hasUI, analysisComplete })
				) {
					return { approved: true, scope: "session" as const };
				}
				// TODO: Check project/global policy grants for bash domain
				return { approved: false, scope: "none" as const };
			},
		});

		// Handle promptNeeded for bash commands
		if (result && "promptNeeded" in result && result.promptNeeded && result.fingerprint) {
			const cmd = String((event.input as any)?.command ?? "");
			const reusableUnsafe = !result.patternAnalysisComplete || (result.patterns?.length ?? 0) === 0;
			
			// For bash tool call guard, all returned patterns are currently missing since it wasn't approved.
			// In the future this could be more granular, but right now if the guard triggers a prompt,
			// the entire command chain needs approval.
			const missingPatternSummary = formatAllowPatternSummary(result.patterns || []);

			const decision = await promptPermission(ctx, {
				target: "local",
				commandPreview: result.commandPreview || buildCommandPreview(cmd),
				commandFull: cmd,
				reusableUnsafe,
				missingPatternSummary,
				domain: "bash",
			});

			if (decision === "deny") {
				await audit({
					event: "bash_tool_call_block",
					reason: "user_denied",
					commandPreview: result.commandPreview,
					fingerprint: result.fingerprint,
				});
				return { block: true, reason: "Blocked by user" };
			}

			if (decision === "allow_session" && !reusableUnsafe) {
				for (const pattern of result.patterns || []) {
					bashSessionGrants.add(computeBashFingerprint(pattern));
				}
			}

			// allow_once or allow_session: proceed (return undefined to allow)
			return undefined;
		}

		return result;
	});

	pi.on("user_bash", async (event) => {
		return handleUserBashGuard(event, {
			guardHealthy,
			matchDirectSsh: directSshMatcher,
			audit,
		});
	});

	pi.registerTool({
		name: "ssh_bash",
		label: "ssh_bash",
		description:
			"Execute remote bash commands over SSH with per-command user approval. New commands require allow once/session/project decisions.",
		parameters: schema,
		async execute(toolCallId, params: any, signal, onUpdate, ctx) {
			if (!guardHealthy) {
				throw new Error("SSH guard unhealthy: extension is in emergency fail-closed mode.");
			}

			const valid = validateSshInput(params);
			if (!valid.ok) {
				throw new Error(`Invalid ssh_bash input: ${valid.reason}`);
			}

			const fingerprint = computeFingerprint({ target: params.target, command: params.command });
			const commandPreview = buildCommandPreview(params.command);
			const patternAnalysis = analyzeCommandPatterns(params.command);

			// Log commands that need pattern improvement
			await logAnalysisResult(params.command, {
				target: params.target,
				cwd: params.cwd,
				patternAnalysisComplete: patternAnalysis.complete,
				patterns: patternAnalysis.patterns,
				reason: patternAnalysis.reason,
			});
			const allowPatternSummary = formatAllowPatternSummary(patternAnalysis.patterns);
			const reusableEntries = patternAnalysis.patterns.map((pattern) => {
				const fallbackPattern = getFallbackPattern(pattern);
				return {
					pattern,
					fingerprint: computeFingerprint({ target: params.target, command: pattern }),
					fallbackFingerprint: fallbackPattern ? computeFingerprint({ target: params.target, command: fallbackPattern }) : undefined,
				};
			});
			const reusableFingerprints = reusableEntries.map((entry) => entry.fingerprint);
			const reusableUnsafe =
				isReusableUnsafe(params.command, params.cwd, patternAnalysis.complete) || !patternAnalysis.complete || reusableFingerprints.length === 0;

			let decision: PermissionDecision | "auto_allow_policy" | "deny_no_ui" = "deny";
			let decisionScope: "none" | "session" | "project" | "global" = "none";

			const approval = await getApprovalFromPolicies(fingerprint, reusableEntries, ctx.hasUI, patternAnalysis.complete);
			if (approval.approved) {
				decision = "auto_allow_policy";
				decisionScope = approval.scope;
			} else if (approval.policyError) {
				const blockedDecision = (ctx.hasUI ? "deny" : "deny_no_ui") as "deny" | "deny_no_ui";
				await audit({
					toolCallId,
					target: params.target,
					fingerprint,
					decision: blockedDecision,
					scope: "none",
					commandPreview,
					allowPatterns: patternAnalysis.patterns,
					patternAnalysisComplete: patternAnalysis.complete,
					result: "blocked",
					reason: "policy_or_trust_load_error",
					error: approval.policyError,
				});
				throw new Error(`Blocked by SSH permission policy (failed to load policy/trust: ${approval.policyError}).`);
			} else if (!ctx.hasUI) {
				decision = "deny_no_ui";
			} else {
				const missing = approval.missingPatterns || [];
				const approved = patternAnalysis.patterns.filter(p => !missing.includes(p));
				const missingPatternSummary = formatAllowPatternSummary(missing);
				const approvedPatternSummary = formatAllowPatternSummary(approved);
				while (true) {
					const chosen = await promptPermission(ctx, {
						target: params.target,
						commandPreview,
						commandFull: params.command,
						reusableUnsafe,
						approvedPatternSummary,
						missingPatternSummary,
						analysisComplete: patternAnalysis.complete,
					});
					if ((chosen === "allow_session" || chosen === "allow_project") && reusableUnsafe) {
						ctx.ui.notify("Reusable approvals are unsafe for this command. Choose Allow Once or Deny.", "warning");
						continue;
					}
					decision = chosen;
					break;
				}
			}

			if (decision === "deny" || decision === "deny_no_ui") {
				await audit({
					toolCallId,
					target: params.target,
					fingerprint,
					decision,
					scope: "none",
					commandPreview,
					allowPatterns: patternAnalysis.patterns,
					patternAnalysisComplete: patternAnalysis.complete,
					result: "blocked",
				});
				throw new Error("Blocked by SSH permission policy.");
			}

			if (decision === "allow_session") {
				for (const reusableFingerprint of reusableFingerprints) {
					sessionGrants.add(reusableFingerprint);
				}
				decisionScope = "session";
			}

			if (decision === "allow_project") {
				try {
					const trustOk = await ensureProjectTrust(ctx);
					if (!trustOk) {
						await audit({
							toolCallId,
							target: params.target,
							fingerprint,
							decision: "deny",
							scope: "none",
							commandPreview,
							result: "blocked",
							reason: "trust_denied_or_cancelled",
						});
						throw new Error("Project trust denied/cancelled. Command blocked.");
					}
					let current = await readProjectPolicy();
					for (const [idx, reusableFingerprint] of reusableFingerprints.entries()) {
						current = upsertGrant(current, {
							fingerprint: reusableFingerprint,
							target: params.target.trim(),
							commandPreview: patternAnalysis.patterns[idx],
							createdAt: now(),
							domain: "ssh",
						});
					}
					await writeProjectPolicy(current);
					decisionScope = "project";
				} catch (e) {
					await audit({
						toolCallId,
						target: params.target,
						fingerprint,
						decision: "deny",
						scope: "none",
						commandPreview,
						result: "blocked",
						reason: "project_persist_failed",
						error: e instanceof Error ? e.message : String(e),
					});
					throw new Error(`Project approval persistence failed. Command denied: ${e instanceof Error ? e.message : String(e)}`);
				}
			}

			const exec = await executeSsh({
				target: params.target,
				command: params.command,
				cwd: params.cwd,
				timeout: params.timeout,
				signal,
				onChunk: (chunk) => {
					onUpdate?.({ content: toToolContent(chunk), details: { partial: true } });
				},
			});

			const executionFailed = exec.timedOut || exec.aborted || (exec.exitCode !== 0 && exec.exitCode !== undefined);

			await audit({
				toolCallId,
				target: params.target,
				fingerprint,
				decision,
				scope: decisionScope,
				commandPreview,
				allowPatterns: patternAnalysis.patterns,
				patternAnalysisComplete: patternAnalysis.complete,
				result: executionFailed ? "failed" : "executed",
				exitCode: exec.exitCode,
			});

			const details = {
				exitCode: exec.exitCode,
				truncated: exec.truncated,
				fullOutputPath: exec.fullOutputPath,
				decision,
				decisionScope,
				fingerprint,
				target: params.target,
				allowPatterns: patternAnalysis.patterns,
			};
			if (exec.timedOut || exec.aborted) {
				throw new Error(exec.text);
			}
			if (exec.exitCode !== 0 && exec.exitCode !== undefined) {
				throw new Error(`${exec.text}\n\nCommand exited with code ${exec.exitCode}`);
			}
			return { content: toToolContent(exec.text), details } as any;
		},
	});
}
