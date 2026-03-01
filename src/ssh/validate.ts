export interface SshToolInput {
	target: string;
	command: string;
	cwd?: string;
	timeout?: number;
}

export function validateSshInput(input: SshToolInput): { ok: true } | { ok: false; reason: string } {
	const target = input.target?.trim();
	if (!target) return { ok: false, reason: "target must not be empty" };
	if (target.startsWith("-")) return { ok: false, reason: "target must not start with '-'" };
	if (target.length > 255) return { ok: false, reason: "target too long" };
	if (/[\u0000\r\n]/.test(target)) return { ok: false, reason: "target contains invalid control characters" };

	const command = input.command?.trim();
	if (!command) return { ok: false, reason: "command must not be empty" };

	if (input.cwd && /[\u0000\r\n]/.test(input.cwd)) {
		return { ok: false, reason: "cwd contains invalid control characters" };
	}

	if (input.timeout !== undefined) {
		if (!Number.isInteger(input.timeout) || input.timeout < 1 || input.timeout > 3600) {
			return { ok: false, reason: "timeout must be an integer between 1 and 3600" };
		}
	}

	return { ok: true };
}
