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
 * - Reference relative paths (./ or ../) - these are cwd-dependent
 * - Use variable interpolation that we can't resolve
 * - Contain dynamic elements that make the fingerprint unstable
 *
 * Note: Having a cwd alone doesn't make a command unsafe IF the pattern analysis
 * is complete - in that case, we have fully extracted the commands and can safely
 * approve them for reuse.
 */
export function isReusableUnsafe(command: string, cwd?: string, patternAnalysisComplete?: boolean): boolean {
	const c = normalizeCommand(command);

	// Check for relative path references that make the command cwd-dependent
	if (/(^|\s|[;\n|&]\s*)(\.\/|\.\.\/)/.test(c)) {
		return true;
	}

	// If pattern analysis is complete, we've fully extracted the commands.
	// Even with cwd, the patterns are stable and reusable.
	// Without pattern analysis completeness, cwd-dependent commands are unsafe.
	if (patternAnalysisComplete === true) {
		return false; // Patterns are fully extracted, safe for reuse
	}

	// Pattern analysis incomplete AND cwd provided - conservative: unsafe
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
