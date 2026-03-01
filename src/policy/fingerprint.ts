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

export function isReusableUnsafe(command: string, cwd?: string): boolean {
	if (cwd && cwd.trim().length > 0) return true;
	const c = normalizeCommand(command);
	return /(^|\s|[;\n|&]\s*)(\.\/|\.\.\/)/.test(c);
}

export function computeBashFingerprint(command: string): string {
	const commandCanonical = normalizeCommand(command);
	const material = `v1:bash\n${commandCanonical}`;
	return createHash("sha256").update(material).digest("hex");
}
