import { createHash } from "node:crypto";

export interface FingerprintInput {
	target: string;
	command: string;
}

export function normalizeTarget(target: string): string {
	return target.trim();
}

export function normalizeCommand(command: string): string {
	const normalizedNewlines = command.replace(/\r\n?/g, "\n");
	const trimmed = normalizedNewlines.trim();
	return trimmed.replace(/\n+$/g, "");
}

export function buildFingerprintInput(input: FingerprintInput): {
	targetCanonical: string;
	commandCanonical: string;
	material: string;
} {
	const targetCanonical = normalizeTarget(input.target);
	const commandCanonical = normalizeCommand(input.command);
	const material = `v1\n${targetCanonical}\n${commandCanonical}`;
	return { targetCanonical, commandCanonical, material };
}

export function computeFingerprint(input: FingerprintInput): string {
	const { material } = buildFingerprintInput(input);
	return createHash("sha256").update(material).digest("hex");
}

export function buildCommandPreview(command: string, maxLen = 120): string {
	const oneLine = normalizeCommand(command).replace(/\s+/g, " ");
	if (oneLine.length <= maxLen) return oneLine;
	return `${oneLine.slice(0, maxLen - 3)}...`;
}

/**
 * Determine if a command is unsafe for reusable approvals.
 *
 * Commands are "reusable-unsafe" if they:
 * - Have a cwd provided (any non-empty cwd makes it unsafe for reusable approval)
 * - Reference relative paths (./ or ../) - these are cwd-dependent
 * - Use variable interpolation that we can't resolve
 * - Contain dynamic elements that make the fingerprint unstable
 *
 * Note: Having cwd always makes a command unsafe for reusable approvals because:
 * - The same command fingerprint can execute in different directories
 * - Session/project approvals should not grant blanket permission across directories
 * - Relative paths (./ ../) remain unsafe regardless of cwd presence
 */
export function isReusableUnsafe(command: string, cwd?: string, patternAnalysisComplete?: boolean): boolean {
	const c = normalizeCommand(command);

	// Check for relative path references that make the command cwd-dependent
	if (/(^|\s|[;\n|&]\s*)(\.\/|\.\.\/)/.test(c)) {
		return true;
	}

	// Any non-empty cwd makes the command unsafe for reusable approvals
	// The key fingerprint excludes cwd, so reusable approvals would grant
	// execution rights across different directories - a security risk
	if (cwd && cwd.trim().length > 0) {
		return true;
	}

	return false;
}

export function computeBashFingerprint(command: string): string {
	const commandCanonical = normalizeCommand(command);
	const material = `v1:bash\n${commandCanonical}`;
	return createHash("sha256").update(material).digest("hex");
}
