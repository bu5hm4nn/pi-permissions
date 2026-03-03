import test from "node:test";
import assert from "node:assert/strict";
import { handleToolCallGuard, type GuardRuntime } from "../src/ssh/guard.ts";
import { computeBashFingerprint } from "../src/policy/fingerprint.ts";

test("bash guard allows URL-scoped pattern if wildcard fallback is approved in session", async () => {
	// The user approved "curl POST *"
	const fallbackFingerprint = computeBashFingerprint("curl POST *");
	
	let approvalChecked = false;
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async (fingerprint, domain, patterns) => {
			approvalChecked = true;
			// Simulate the check logic in index.ts
			const isApproved = (p: string) => {
				const fp = computeBashFingerprint(p);
				if (fp === fallbackFingerprint) return true; // Pretend it's in sessionGrants
				// Let's implement the actual logic:
				let approved = false;
				if (fp === fallbackFingerprint) approved = true;
				// check fallback
				const parts = p.split(" ");
				if (parts.length >= 3 && parts[0] === "curl") {
					const fallback = `${parts[0]} ${parts[1]} *`;
					if (computeBashFingerprint(fallback) === fallbackFingerprint) approved = true;
				}
				return approved;
			};
			
			if (patterns && patterns.every(isApproved)) {
				return { approved: true, scope: "session" as const };
			}
			return { approved: false, scope: "none" as const };
		},
	};

	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "curl -X POST https://api.example.com/user" } }, runtime);

	assert.ok(approvalChecked, "Should check bash approval");
	assert.equal(result, undefined, "Should pass through without prompting because fallback is approved");
});
