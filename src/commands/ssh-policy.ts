import { chmod, mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import type { ExtensionAPI, ExtensionCommandContext } from "@mariozechner/pi-coding-agent";
import { analyzeCommandPatterns, getFallbackPattern } from "../policy/command-patterns.ts";
import { computeFingerprint } from "../policy/fingerprint.ts";
import { emptyPolicyFile, type PolicyFile } from "../policy/schema.ts";
import { readPermissionsConfig, resolveProjectRoot } from "../policy/store.ts";

export interface PolicyCommandState {
	getSessionFingerprints: () => Set<string>;
	clearSession: () => void;
	revokeSessionByPrefix: (prefix: string) => { ok: boolean; message: string };
	readGlobal: () => Promise<PolicyFile>;
	readProject: () => Promise<PolicyFile>;
	isProjectTrusted: () => Promise<boolean>;
	writeGlobal: (policy: PolicyFile) => Promise<void>;
	writeProject: (policy: PolicyFile) => Promise<void>;
	revokeGlobalByPrefix: (prefix: string) => Promise<{ ok: boolean; message: string }>;
	revokeProjectByPrefix: (prefix: string) => Promise<{ ok: boolean; message: string }>;
	reload: () => Promise<void>;
}

interface ListRow {
	fingerprint: string;
	target: string;
	commandPreview: string;
	createdAt: string;
	source: string;
}

interface PermissionsMvpFile {
	version: 1;
	updatedAt: string;
	permissions: {
		ssh: { enabled: boolean };
		bash: { enabled: boolean };
	};
}

function toPermissionsMvpFile(values: { sshEnabled?: unknown; bashEnabled?: unknown }): PermissionsMvpFile {
	return {
		version: 1,
		updatedAt: new Date().toISOString(),
		permissions: {
			ssh: { enabled: Boolean(values.sshEnabled) },
			bash: { enabled: Boolean(values.bashEnabled) },
		},
	};
}

function resolveGlobalPermissionsPath(): { piDir: string; agentDir: string; permissionsPath: string } {
	const home = process.env.HOME || homedir();
	if (!home || !isAbsolute(home)) {
		throw new Error("Unable to resolve absolute home directory for global permissions path");
	}
	const piDir = join(home, ".pi");
	const agentDir = join(piDir, "agent");
	return { piDir, agentDir, permissionsPath: join(agentDir, "permissions.json") };
}

async function persistPermissionsMvp(scope: "global" | "project", cwd: string, values: { sshEnabled?: unknown; bashEnabled?: unknown }) {
	const file = toPermissionsMvpFile(values);
	if (scope === "project") {
		// Resolve project root (git root) to ensure consistent path regardless of cwd
		const projectRoot = resolveProjectRoot(cwd);
		const projectDir = join(projectRoot, ".pi");
		const projectPath = join(projectDir, "permissions.json");
		await mkdir(projectDir, { recursive: true, mode: 0o700 });
		await chmod(projectDir, 0o700);
		await writeFile(projectPath, JSON.stringify(file, null, 2), { encoding: "utf-8", mode: 0o600 });
		await chmod(projectPath, 0o600);
		return;
	}
	const { piDir, agentDir, permissionsPath } = resolveGlobalPermissionsPath();
	await mkdir(piDir, { recursive: true, mode: 0o700 });
	await chmod(piDir, 0o700);
	await mkdir(agentDir, { recursive: true, mode: 0o700 });
	await chmod(agentDir, 0o700);
	await writeFile(permissionsPath, JSON.stringify(file, null, 2), { encoding: "utf-8", mode: 0o600 });
	await chmod(permissionsPath, 0o600);
}

function permissionsPanel() {
	return {
		title: "Permissions",
		toggles: [
			{ type: "toggle", name: "sshEnabled", label: "SSH permissions", checked: true },
			{ type: "toggle", name: "bashEnabled", label: "Bash permissions", checked: true },
		],
		actions: [{ label: "Save" }, { label: "Cancel" }],
	};
}

function usage(ctx: ExtensionCommandContext, command: "list" | "revoke" | "explain") {
	if (command === "list") {
		ctx.ui.notify("Usage: /ssh-policy list [session|project|global|effective]", "error");
		return;
	}
	if (command === "explain") {
		ctx.ui.notify("Usage: /ssh-policy explain <target> <command>", "error");
		return;
	}
	ctx.ui.notify("Usage: /ssh-policy revoke <session|project|global> <fingerprintPrefix>=8+ hex", "error");
}

function formatRows(scope: string, rows: ListRow[]): string {
	const lines = [`Scope: ${scope}`, `Grants: ${rows.length}`, "#  fingerprint     source   target              createdAt                preview"];
	for (const [i, row] of rows.entries()) {
		const fp = row.fingerprint.slice(0, 12);
		const source = row.source.padEnd(8).slice(0, 8);
		const target = (row.target || "-").padEnd(18).slice(0, 18);
		const created = (row.createdAt || "-").padEnd(24).slice(0, 24);
		lines.push(`${String(i + 1).padStart(2, " ")} ${fp}  ${source} ${target} ${created} ${row.commandPreview || "-"}`);
	}
	return lines.join("\n");
}

function isPlaceholderValue(v: string): boolean {
	return !v || v === "-" || v === "(session)";
}

function setHasExactOrFallback(fingerprint: string, fallbackFingerprint: string | undefined, set: Set<string>): "exact" | "fallback" | "none" {
	if (set.has(fingerprint)) return "exact";
	if (fallbackFingerprint && set.has(fallbackFingerprint)) return "fallback";
	return "none";
}

function mergeRows(rows: ListRow[]): ListRow[] {
	const byFp = new Map<string, ListRow>();
	for (const row of rows) {
		const existing = byFp.get(row.fingerprint);
		if (!existing) {
			byFp.set(row.fingerprint, row);
			continue;
		}
		const sources = new Set([...existing.source.split("+"), ...row.source.split("+")]);
		const merged: ListRow = { ...existing, source: Array.from(sources).sort().join("+") };
		if (isPlaceholderValue(merged.target) && !isPlaceholderValue(row.target)) merged.target = row.target;
		if (isPlaceholderValue(merged.commandPreview) && !isPlaceholderValue(row.commandPreview)) merged.commandPreview = row.commandPreview;
		if (isPlaceholderValue(merged.createdAt) && !isPlaceholderValue(row.createdAt)) merged.createdAt = row.createdAt;
		byFp.set(row.fingerprint, merged);
	}
	return Array.from(byFp.values());
}

async function doClear(scope: string, state: PolicyCommandState, ctx: ExtensionCommandContext) {
	if (scope === "session" || scope === "all") state.clearSession();
	if (scope === "global" || scope === "all") await state.writeGlobal(emptyPolicyFile());
	if (scope === "project" || scope === "all") await state.writeProject(emptyPolicyFile());
	ctx.ui.notify(`Cleared ${scope} policy scope`, "info");
}

// Deprecation warning shown once per session
let sshPolicyDeprecationShown = false;

/**
 * Reset deprecation flag (for testing purposes only)
 */
export function resetSshPolicyDeprecationFlag() {
	sshPolicyDeprecationShown = false;
}

function showDeprecationNoticeIfNeeded(ctx: ExtensionCommandContext) {
	if (!sshPolicyDeprecationShown) {
		sshPolicyDeprecationShown = true;
		ctx.ui.notify(
			"/ssh-policy is deprecated. Use /permissions for a unified permissions panel.",
			"warning"
		);
	}
}

export function registerPolicyCommands(pi: ExtensionAPI, state: PolicyCommandState) {
	pi.registerCommand("permissions", {
		description: "Configure SSH/Bash permissions",
		handler: async (_args, ctx) => {
			if (!ctx.hasUI) {
				ctx.ui.notify("/permissions requires UI mode", "error");
				return;
			}
			try {
				const cwd = ctx.cwd || process.cwd();
				const config = await readPermissionsConfig(cwd);

				// Interactive loop for toggling permissions
				while (true) {
					// Build menu options showing current state
					const sshStatus = config.ssh.enabled ? "✓" : "○";
					const bashStatus = config.bash.enabled ? "✓" : "○";

					const choice = await ctx.ui.select("Permissions Configuration", [
						`[${sshStatus}] SSH permissions (${config.ssh.enabled ? "enabled" : "disabled"})`,
						`[${bashStatus}] Bash permissions (${config.bash.enabled ? "enabled" : "disabled"})`,
						"───────────────────",
						"Save to global (~/.pi/agent/permissions.json)",
						"Save to project (.pi/permissions.json)",
						"Cancel",
					]);

					if (!choice || choice === "Cancel" || choice.startsWith("───")) {
						return;
					}

					// Toggle SSH
					if (choice.includes("SSH permissions")) {
						config.ssh.enabled = !config.ssh.enabled;
						continue; // Re-show menu with updated state
					}

					// Toggle Bash
					if (choice.includes("Bash permissions")) {
						config.bash.enabled = !config.bash.enabled;
						continue; // Re-show menu with updated state
					}

					// Save to global
					if (choice.includes("global")) {
						await persistPermissionsMvp("global", cwd, {
							sshEnabled: config.ssh.enabled,
							bashEnabled: config.bash.enabled,
						});
						ctx.ui.notify("Permissions saved to global config", "info");
						return;
					}

					// Save to project
					if (choice.includes("project")) {
						await persistPermissionsMvp("project", cwd, {
							sshEnabled: config.ssh.enabled,
							bashEnabled: config.bash.enabled,
						});
						ctx.ui.notify("Permissions saved to project config", "info");
						return;
					}
				}
			} catch (e) {
				ctx.ui.notify(`Failed to handle /permissions: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		},
	});

	pi.registerCommand("ssh-policy", {
		description: "Manage ssh permission policy (list|clear|revoke|reload) [deprecated: use /permissions]",
		handler: async (args, ctx) => {
			// Show deprecation notice before any output
			showDeprecationNoticeIfNeeded(ctx);

			const [cmd = "list", scope = "effective", prefix] = args.trim().split(/\s+/).filter(Boolean);

			if (cmd === "reload") {
				try {
					await state.reload();
					ctx.ui.notify("SSH policy/trust reloaded", "info");
				} catch (e) {
					ctx.ui.notify(`Reload failed: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
				return;
			}

			if (cmd === "explain") {
				const tokens = args.trim().split(/\s+/).filter(Boolean);
				const target = tokens[1] || "";
				const command = tokens.slice(2).join(" ");
				if (!target || !command) {
					usage(ctx, "explain");
					return;
				}

				const analysis = analyzeCommandPatterns(command);
				const exactFingerprint = computeFingerprint({ target, command });
				const sessionSet = state.getSessionFingerprints();
				const global = await state.readGlobal();
				const trustedProject = await state.isProjectTrusted();
				const project = trustedProject ? await state.readProject() : emptyPolicyFile();
				const globalSet = new Set(global.grants.map((g) => g.fingerprint));
				const projectSet = new Set(project.grants.map((g) => g.fingerprint));
				const effectiveSet = new Set([...globalSet, ...(trustedProject ? Array.from(projectSet) : []), ...Array.from(sessionSet)]);

				const patternLines = analysis.patterns.map((pattern, idx) => {
					const fingerprint = computeFingerprint({ target, command: pattern });
					const fallbackPattern = getFallbackPattern(pattern);
					const fallbackFingerprint = fallbackPattern ? computeFingerprint({ target, command: fallbackPattern }) : undefined;
					const approvedIn = (set: Set<string>) => set.has(fingerprint) || (!!fallbackFingerprint && set.has(fallbackFingerprint));
					const matchType =
						approvedIn(effectiveSet)
							? setHasExactOrFallback(fingerprint, fallbackFingerprint, effectiveSet)
							: "none";
					return [
						`${idx + 1}. pattern=${pattern}`,
						`   fingerprint=${fingerprint}`,
						fallbackPattern ? `   fallback=${fallbackPattern}` : "   fallback=-",
						`   approved: session=${approvedIn(sessionSet)} global=${approvedIn(globalSet)} project=${approvedIn(projectSet)} effective=${approvedIn(effectiveSet)} (${matchType})`,
					].join("\n");
				});

				const reusableApproved =
					analysis.patterns.length > 0 &&
					analysis.patterns.every((pattern) => {
						const fp = computeFingerprint({ target, command: pattern });
						const fallback = getFallbackPattern(pattern);
						const fallbackFp = fallback ? computeFingerprint({ target, command: fallback }) : undefined;
						return effectiveSet.has(fp) || (!!fallbackFp && effectiveSet.has(fallbackFp));
					});
				const exactApproved =
					sessionSet.has(exactFingerprint) || globalSet.has(exactFingerprint) || (trustedProject && projectSet.has(exactFingerprint));
				const decisionReason = exactApproved
					? "exact_fingerprint_approved"
					: reusableApproved
						? "all_reusable_patterns_approved"
						: analysis.patterns.length === 0
							? "no_patterns_extracted"
							: "missing_required_patterns";

				ctx.ui.notify(
					[
						"Scope: explain",
						`Target: ${target}`,
						`Command: ${command}`,
						`Analysis complete: ${analysis.complete}`,
						`Exact fingerprint: ${exactFingerprint}`,
						`Exact approved: ${exactApproved}`,
						`Reusable approved: ${reusableApproved}`,
						`Would auto-approve: ${exactApproved || reusableApproved}`,
						`Decision reason: ${decisionReason}`,
						"Patterns:",
						...(patternLines.length > 0 ? patternLines : ["- none"]),
					].join("\n"),
					"info",
				);
				return;
			}

			if (cmd === "list") {
				if (!["session", "project", "global", "effective"].includes(scope)) {
					usage(ctx, "list");
					return;
				}

				const sessionRows: ListRow[] = Array.from(state.getSessionFingerprints()).map((fp) => ({
					fingerprint: fp,
					target: "-",
					commandPreview: "-",
					createdAt: "-",
					source: "session",
				}));
				const globalRows: ListRow[] = (await state.readGlobal()).grants.map((g) => ({ ...g, source: "global" }));
				const trustedProject = await state.isProjectTrusted();
				const projectRows: ListRow[] = trustedProject
					? (await state.readProject()).grants.map((g) => ({ ...g, source: "project" }))
					: [];

				if (scope === "session") {
					ctx.ui.notify(formatRows("session", sessionRows), "info");
					return;
				}
				if (scope === "global") {
					ctx.ui.notify(formatRows("global", globalRows), "info");
					return;
				}
				if (scope === "project") {
					if (!trustedProject) {
						ctx.ui.notify("Scope: project\nProject is not trusted; no effective project grants.", "info");
						return;
					}
					ctx.ui.notify(formatRows("project", projectRows), "info");
					return;
				}

				const effective = mergeRows([...(ctx.hasUI ? sessionRows : []), ...globalRows, ...projectRows]);
				ctx.ui.notify(formatRows("effective", effective), "info");
				return;
			}

			if (cmd === "clear") {
				const clearScope = scope;
				if (!["session", "project", "global", "all"].includes(clearScope)) {
					ctx.ui.notify("Usage: /ssh-policy clear <session|project|global|all>", "error");
					return;
				}
				if (ctx.hasUI && ["project", "global", "all"].includes(clearScope)) {
					const ok = await ctx.ui.confirm("Clear policy", `Clear ${clearScope} policy entries?`);
					if (!ok) return;
				}
				await doClear(clearScope, state, ctx);
				return;
			}

			if (cmd === "revoke") {
				if (!prefix || !/^[0-9a-fA-F]{8,}$/.test(prefix)) {
					usage(ctx, "revoke");
					return;
				}
				if (scope === "session") {
					const result = state.revokeSessionByPrefix(prefix.toLowerCase());
					ctx.ui.notify(result.message, result.ok ? "info" : "error");
					return;
				}
				if (scope === "global" || scope === "project") {
					const result =
						scope === "global" ? await state.revokeGlobalByPrefix(prefix.toLowerCase()) : await state.revokeProjectByPrefix(prefix.toLowerCase());
					ctx.ui.notify(result.message, result.ok ? "info" : "error");
					return;
				}
				usage(ctx, "revoke");
				return;
			}

			ctx.ui.notify("Usage: /ssh-policy <list|clear|revoke|reload|explain>", "error");
		},
	});
}
