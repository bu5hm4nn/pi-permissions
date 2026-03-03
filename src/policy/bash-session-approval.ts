import { computeBashFingerprint } from "./fingerprint.ts";
import { getFallbackPattern } from "./command-patterns.ts";

export function isBashSessionApproved(input: {
	fingerprint: string;
	patterns?: string[];
	bashSessionGrants: Set<string>;
	hasUI: boolean;
	analysisComplete?: boolean;
}): boolean {
	const { fingerprint, patterns, bashSessionGrants, hasUI, analysisComplete = true } = input;

	if (!hasUI) {
		return false;
	}

	if (bashSessionGrants.has(fingerprint)) {
		return true;
	}

	const isApproved = (pattern: string) => {
		if (bashSessionGrants.has(computeBashFingerprint(pattern))) return true;
		const fallback = getFallbackPattern(pattern);
		return fallback ? bashSessionGrants.has(computeBashFingerprint(fallback)) : false;
	};

	if (analysisComplete && patterns && patterns.length > 0 && patterns.every(isApproved)) {
		return true;
	}

	return false;
}
