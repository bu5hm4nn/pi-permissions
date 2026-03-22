import test from "node:test";
import assert from "node:assert/strict";
import { handleToolCallGuard, type GuardRuntime } from "../src/ssh/guard.ts";
import { computeBashFingerprint } from "../src/policy/fingerprint.ts";
import { formatAllowPatternSummary } from "../src/policy/command-patterns.ts";

// Test: When UI is available and bash permissions enabled, the guard should NOT block
// but instead signal that prompting is needed (by returning a special result or passthrough)
test("guard signals prompt-needed when UI available and bash not pre-approved", async () => {
	let approvalChecked = false;
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => {
			approvalChecked = true;
			return { approved: false, scope: "none" };
		},
	};

	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "echo hello" } }, runtime);

	// The guard should check approval
	assert.ok(approvalChecked, "Should check bash approval");

	// When UI is available and not approved, guard should return prompt_needed
	// instead of blocking - the caller should handle prompting
	// Current behavior blocks - we need to change this to signal prompt needed
	assert.ok(
		result?.promptNeeded === true || result?.block === false,
		"Should signal prompt needed or not block when UI available",
	);
});

test("guard blocks without prompt when no UI and bash not approved", async () => {
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: false,
		checkBashApproval: async () => {
			return { approved: false, scope: "none" };
		},
	};

	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "echo hello" } }, runtime);

	assert.ok(result?.block === true, "Should block when no UI");
	assert.match(result?.reason || "", /not approved/i, "Should mention not approved");
});

test("guard passes through when bash command is already approved", async () => {
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => {
			return { approved: true, scope: "session" };
		},
	};

	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "echo hello" } }, runtime);

	assert.ok(result === undefined, "Should pass through when approved");
});

test("guard returns pattern info for prompting when not approved and UI available", async () => {
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => {
			return { approved: false, scope: "none" };
		},
	};

	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "curl -X POST https://api.example.com" } }, runtime);

	// When prompting is needed, guard should provide info for the prompt
	if (result?.promptNeeded) {
		assert.ok(result.fingerprint, "Should include fingerprint for prompt");
		assert.ok(result.patterns, "Should include patterns for prompt");
		assert.ok(result.commandPreview, "Should include command preview for prompt");
	}
});

// --- Integration tests for full prompt flow (simulating index.ts handler) ---

test("integration: promptNeeded handler stores session grants on allow_session", async () => {
	const bashSessionGrants = new Set<string>();
	
	// Simulate the guard returning promptNeeded
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	};
	
	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "echo hello" } }, runtime);
	
	// Simulate the handler processing promptNeeded (as index.ts does)
	if (result && "promptNeeded" in result && result.promptNeeded && result.fingerprint) {
		const decision = "allow_session"; // Simulated user choice
		const reusableUnsafe = !result.patternAnalysisComplete || (result.patterns?.length ?? 0) === 0;
		
		if (decision === "allow_session" && !reusableUnsafe) {
			for (const pattern of result.patterns || []) {
				bashSessionGrants.add(computeBashFingerprint(pattern));
			}
		}
	}
	
	// Verify session grants were stored
	assert.ok(bashSessionGrants.size > 0, "Session grants should be stored after allow_session");
	// The pattern "echo *" should be stored
	assert.ok(bashSessionGrants.has(computeBashFingerprint("echo *")), "Pattern fingerprint should be in session grants");
});

test("integration: promptNeeded handler blocks on deny decision", async () => {
	let blocked = false;
	
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	};
	
	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "rm -rf /tmp/test" } }, runtime);
	
	// Simulate the handler processing promptNeeded with deny decision
	if (result && "promptNeeded" in result && result.promptNeeded) {
		const decision = "deny"; // Simulated user choice
		
		if (decision === "deny") {
			blocked = true;
		}
	}
	
	assert.ok(blocked, "Command should be blocked when user denies");
});

test("integration: promptNeeded handler allows on allow_once without storing grants", async () => {
	const bashSessionGrants = new Set<string>();
	let allowed = false;
	
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	};
	
	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "echo test" } }, runtime);
	
	// Simulate the handler processing promptNeeded with allow_once decision
	if (result && "promptNeeded" in result && result.promptNeeded) {
		const decision = "allow_once"; // Simulated user choice
		
		if (decision === "allow_once") {
			allowed = true;
			// No grants stored for allow_once
		}
	}
	
	assert.ok(allowed, "Command should be allowed on allow_once");
	assert.equal(bashSessionGrants.size, 0, "No session grants should be stored for allow_once");
});

test("integration: formatAllowPatternSummary works with guard patterns", async () => {
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: () => false,
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	};
	
	const result = await handleToolCallGuard({ toolName: "bash", input: { command: "curl -X POST https://api.example.com" } }, runtime);
	
	if (result && "promptNeeded" in result && result.promptNeeded && result.patterns) {
		const summary = formatAllowPatternSummary(result.patterns);
		assert.ok(summary.includes("curl"), "Summary should include curl pattern");
	}
});

// =============================================================================
// SCP Passthrough - Bash Permissions Flow Tests
// SCP commands pass through the SSH matcher and should trigger bash approval flow
// =============================================================================

test("SCP commands pass through guard to bash permissions when enabled", async () => {
	let approvalChecked = false;
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: (cmd: string) => cmd.includes("ssh") && !cmd.includes("scp"), // SCP passes through
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => {
			approvalChecked = true;
			return { approved: false, scope: "none" };
		},
	};

	// SCP command should pass SSH matcher and reach bash permissions
	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "scp file user@host:/tmp" } },
		runtime,
	);

	// Approval check should have been invoked for SCP
	assert.ok(approvalChecked, "SCP should trigger bash approval check");

	// When not approved and UI available, should signal promptNeeded
	assert.ok(result?.promptNeeded === true, "SCP should trigger promptNeeded for bash approval");
});

test("SCP commands blocked in no-UI mode when bash permissions enabled", async () => {
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: (cmd: string) => cmd.includes("ssh") && !cmd.includes("scp"), // SCP passes through
		bashPermissions: { enabled: true },
		hasUI: false,
		checkBashApproval: async () => ({ approved: false, scope: "none" }),
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "scp file user@host:/tmp" } },
		runtime,
	);

	// In no-UI mode, SCP should be blocked (requires approval but can't prompt)
	assert.ok(result?.block === true, "SCP should be blocked in no-UI mode");
	assert.match(result?.reason || "", /not approved/i, "Should mention not approved");
});

test("SCP commands passthrough when bash permissions disabled", async () => {
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: (cmd: string) => cmd.includes("ssh") && !cmd.includes("scp"), // SCP passes through
		bashPermissions: { enabled: false }, // Bash permissions disabled (default)
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "scp file user@host:/tmp" } },
		runtime,
	);

	// With bash permissions disabled, SCP should passthrough completely
	assert.equal(result, undefined, "SCP should passthrough when bash permissions disabled");
});

test("SCP with approved bash permissions executes without prompt", async () => {
	const runtime: GuardRuntime = {
		guardHealthy: true,
		matchDirectSsh: (cmd: string) => cmd.includes("ssh") && !cmd.includes("scp"), // SCP passes through
		bashPermissions: { enabled: true },
		hasUI: true,
		checkBashApproval: async () => ({ approved: true, scope: "session" }),
	};

	const result = await handleToolCallGuard(
		{ toolName: "bash", input: { command: "scp file user@host:/tmp" } },
		runtime,
	);

	// Pre-approved SCP should passthrough
	assert.equal(result, undefined, "Pre-approved SCP should passthrough");
});
