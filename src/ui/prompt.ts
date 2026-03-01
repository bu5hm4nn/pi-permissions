import type { ExtensionContext } from "@mariozechner/pi-coding-agent";

export type PermissionDecision = "allow_once" | "allow_session" | "allow_project" | "deny";

const OPTIONS_ALL = ["1. Allow Once", "2. Allow for this session", "3. Allow for this Project", "4. Deny"];
const OPTIONS_RESTRICTED = ["1. Allow Once", "2. Deny"];

export async function promptPermission(
	ctx: ExtensionContext,
	preview: {
		target: string;
		commandPreview: string;
		commandFull?: string;
		reusableUnsafe: boolean;
		allowPatternSummary?: string;
		missingPatternSummary?: string;
		analysisComplete?: boolean;
	},
): Promise<PermissionDecision> {
	if (!ctx.hasUI) return "deny";
	const allowLine = preview.allowPatternSummary
		? `\nAllow for session/project will grant: ${preview.allowPatternSummary}`
		: "";
	const missingLine = preview.missingPatternSummary
		? `\nMissing approval(s) for this target: ${preview.missingPatternSummary}`
		: "";
	const analysisNote = preview.analysisComplete === false
		? "\n\nNote: Could not fully determine all executable commands. Reusable approvals are disabled for safety."
		: "";
	const unsafeNote = preview.reusableUnsafe
		? "\n\nNote: Reusable approvals are unavailable for this command."
		: "";
	const options = preview.reusableUnsafe ? OPTIONS_RESTRICTED : OPTIONS_ALL;
	const commandText = preview.commandFull && preview.commandFull.trim().length > 0 ? preview.commandFull : preview.commandPreview;
	const selected = await ctx.ui.select(
		`SSH command requires approval\n\nTarget: ${preview.target}\nCommand: ${commandText}${allowLine}${missingLine}${analysisNote}${unsafeNote}`,
		options,
	);
	if (!selected) return "deny";
	if (selected === "1. Allow Once") return "allow_once";
	if (selected === "2. Allow for this session") return "allow_session";
	if (selected === "3. Allow for this Project") return "allow_project";
	return "deny";
}
