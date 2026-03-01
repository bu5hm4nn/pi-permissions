import { constants as fsConstants, existsSync } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";
import { registerPolicyCommands } from "./commands/ssh-policy";
import { analyzeCommandPatterns, formatAllowPatternSummary } from "./policy/command-patterns";
import { buildCommandPreview, computeFingerprint, isReusableUnsafe } from "./policy/fingerprint";
import type { PolicyFile } from "./policy/schema";
import { emptyPolicyFile } from "./policy/schema";
import {
	readPolicy,
	removeGrantByPrefix,
	resolveStorePaths,
	type StorePaths,
	upsertGrant,
	writePolicy,
} from "./policy/store";
import { isProjectTrusted, trustProject } from "./policy/trust";
import { executeSsh, toToolContent } from "./ssh/execute";
import { handleToolCallGuard, handleUserBashGuard } from "./ssh/guard";
import { isDirectSshFamilyCommand } from "./ssh/matcher";
import { validateSshInput } from "./ssh/validate";
import { promptPermission, type PermissionDecision } from "./ui/prompt";

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
	directSshMatcher?: (command: string) => boolean;
}

export default function sshPermissionExtension(pi: ExtensionAPI, options?: SshPermissionExtensionOptions) {
	const directSshMatcher = options?.directSshMatcher ?? isDirectSshFamilyCommand;
	let paths: StorePaths | null = null;
	let sessionGrants = new Set<string>();
	let guardHealthy = true;

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

		const matcherCases: Array<{ command: string; expectedBlocked: boolean }> = [
			{ command: "echo ok", expectedBlocked: false },
			{ command: "FOO=bar", expectedBlocked: false },
			{ command: "echo hi > out.txt", expectedBlocked: false },
			{ command: "ssh user@host", expectedBlocked: true },
			{ command: "\\ssh user@host", expectedBlocked: true },
			{ command: "sudo -- ssh user@host", expectedBlocked: true },
			{ command: "\\sudo -- \\ssh user@host", expectedBlocked: true },
			{ command: "echo 'unterminated", expectedBlocked: true },
			{ command: "echo ok &&", expectedBlocked: true },
		];
		for (const c of matcherCases) {
			let blocked = true;
			try {
				blocked = directSshMatcher(c.command);
			} catch {
				blocked = true;
			}
			if (blocked !== c.expectedBlocked) {
				throw new Error(`matcher self-check failed for command: ${c.command}`);
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
		reusableEntries: Array<{ fingerprint: string; pattern: string }>,
		hasUI: boolean,
	): Promise<{
		approved: boolean;
		scope: "none" | "session" | "project" | "global";
		policyError?: string;
		missingPatterns?: string[];
	}> {
		const reusableFingerprints = reusableEntries.map((e) => e.fingerprint);
		const sessionApprovedExact = hasUI && sessionGrants.has(exactFingerprint);
		const sessionApprovedReusableOnly =
			hasUI && reusableFingerprints.length > 0 && reusableFingerprints.every((fingerprint) => sessionGrants.has(fingerprint));
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

			const reusableSatisfiedBySession =
				hasUI && reusableFingerprints.length > 0 && reusableFingerprints.every((fingerprint) => sessionEffective.has(fingerprint));
			const reusableSatisfiedByPersistent =
				reusableFingerprints.length > 0 && reusableFingerprints.every((fingerprint) => persistentEffective.has(fingerprint));

			if (sessionApprovedExact || reusableSatisfiedBySession) return { approved: true, scope: "session" };
			if (globalSet.has(exactFingerprint)) return { approved: true, scope: "global" };
			if (trustedProject && projectSet.has(exactFingerprint)) return { approved: true, scope: "project" };
			if (reusableSatisfiedByPersistent) {
				const hasProjectComponent = trustedProject && reusableFingerprints.some((fingerprint) => projectSet.has(fingerprint));
				return { approved: true, scope: hasProjectComponent ? "project" : "global" };
			}
			const missingPatterns = reusableEntries
				.filter((entry) => !sessionEffective.has(entry.fingerprint))
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
	});

	pi.on("session_start", async (_event, ctx) => {
		sessionGrants = new Set();
		try {
			paths = await runStartupSelfCheck(ctx.cwd);
			guardHealthy = true;
			ctx.ui.setStatus("ssh-policy", ctx.ui.theme.fg("accent", "ssh-permission: active"));
		} catch (e) {
			guardHealthy = false;
			paths = null;
			ctx.ui.setStatus("ssh-policy", ctx.ui.theme.fg("error", "ssh-permission: fail-closed"));
			ctx.ui.notify(`ssh-permission startup self-check failed: ${e instanceof Error ? e.message : String(e)}`, "error");
		}
	});

	const clearSessionGrants = () => {
		sessionGrants = new Set();
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

	pi.on("tool_call", async (event) => {
		return handleToolCallGuard(event, {
			guardHealthy,
			matchDirectSsh: directSshMatcher,
			audit,
		});
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
			const allowPatternSummary = formatAllowPatternSummary(patternAnalysis.patterns);
			const reusableEntries = patternAnalysis.patterns.map((pattern) => ({
				pattern,
				fingerprint: computeFingerprint({ target: params.target, command: pattern }),
			}));
			const reusableFingerprints = reusableEntries.map((entry) => entry.fingerprint);
			const reusableUnsafe =
				isReusableUnsafe(params.command, params.cwd) || !patternAnalysis.complete || reusableFingerprints.length === 0;

			let decision: PermissionDecision | "auto_allow_policy" | "deny_no_ui" = "deny";
			let decisionScope: "none" | "session" | "project" | "global" = "none";

			const approval = await getApprovalFromPolicies(fingerprint, reusableEntries, ctx.hasUI);
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
				const missingPatternSummary = formatAllowPatternSummary(approval.missingPatterns || []);
				while (true) {
					const chosen = await promptPermission(ctx, {
						target: params.target,
						commandPreview,
						commandFull: params.command,
						reusableUnsafe,
						allowPatternSummary,
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
