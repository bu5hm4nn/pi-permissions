import type { ExtensionContext } from "@mariozechner/pi-coding-agent";

export type PermissionDecision = "allow_once" | "allow_session" | "allow_project" | "deny";

const OPTIONS_ALL = ["1. Allow Once", "2. Allow for this session", "3. Allow for this Project", "4. Deny"];
const OPTIONS_BASH = ["1. Allow Once", "2. Allow for this session", "3. Deny"]; // No project/global option for bash
const OPTIONS_RESTRICTED = ["1. Allow Once", "2. Deny"];

export type PermissionDomain = "ssh" | "bash";

export async function promptPermission(
	ctx: ExtensionContext,
	preview: {
		target: string;
		commandPreview: string;
		commandFull?: string;
		reusableUnsafe: boolean;
		allowPatternSummary?: string;
		approvedPatternSummary?: string;
		missingPatternSummary?: string;
		analysisComplete?: boolean;
		domain?: PermissionDomain;
	},
): Promise<PermissionDecision> {
	if (!ctx.hasUI) return "deny";
	const domain = preview.domain ?? "ssh";
	const domainLabel = domain === "bash" ? "Bash" : "SSH";
	const approvedLine = preview.approvedPatternSummary
		? `\nPatterns already approved: ${preview.approvedPatternSummary}`
		: "";
	const missingLine = preview.missingPatternSummary
		? `\nPatterns requiring approval: ${preview.missingPatternSummary}`
		: "";
	const analysisNote = preview.analysisComplete === false
		? "\n\nNote: Could not fully determine all executable commands. Reusable approvals are disabled for safety."
		: "";
	const unsafeNote = preview.reusableUnsafe
		? "\n\nNote: Reusable approvals are unavailable for this command."
		: "";
	const options = preview.reusableUnsafe
		? OPTIONS_RESTRICTED
		: domain === "bash"
			? OPTIONS_BASH
			: OPTIONS_ALL;
	const commandText = preview.commandFull && preview.commandFull.trim().length > 0 ? preview.commandFull : preview.commandPreview;
	const targetLine = domain === "ssh" ? `\nTarget: ${preview.target}` : "";
	const selected = await ctx.ui.select(
		`${domainLabel} command requires approval${targetLine}\nCommand: ${commandText}${approvedLine}${missingLine}${analysisNote}${unsafeNote}`,
		options,
	);
	if (!selected) return "deny";
	if (selected === "1. Allow Once") return "allow_once";
	if (selected === "2. Allow for this session") return "allow_session";
	if (selected === "3. Allow for this Project") return "allow_project";
	return "deny";
}
