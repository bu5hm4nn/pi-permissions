import test from "node:test";
import assert from "node:assert/strict";
import { promptPermission } from "../src/ui/prompt.ts";

test("promptPermission displays 'SSH Permission' for ssh domain (default)", async () => {
	let capturedText = "";
	const ctx: any = {
		hasUI: true,
		ui: {
			select: async (text: string) => {
				capturedText = text;
				return "4. Deny";
			},
		},
	};

	await promptPermission(ctx, {
		target: "user@example.com",
		commandPreview: "ls -la",
		reusableUnsafe: false,
	});

	assert.match(capturedText, /SSH command requires approval/i, "Default should show SSH domain");
});

test("promptPermission displays 'SSH Permission' for explicit ssh domain", async () => {
	let capturedText = "";
	const ctx: any = {
		hasUI: true,
		ui: {
			select: async (text: string) => {
				capturedText = text;
				return "4. Deny";
			},
		},
	};

	await promptPermission(ctx, {
		target: "user@example.com",
		commandPreview: "ls -la",
		reusableUnsafe: false,
		domain: "ssh",
	});

	assert.match(capturedText, /SSH command requires approval/i, "Explicit ssh domain should show SSH");
});

test("promptPermission displays 'Bash Permission' for bash domain", async () => {
	let capturedText = "";
	const ctx: any = {
		hasUI: true,
		ui: {
			select: async (text: string) => {
				capturedText = text;
				return "4. Deny";
			},
		},
	};

	await promptPermission(ctx, {
		target: "local",
		commandPreview: "rm -rf /tmp/test",
		reusableUnsafe: false,
		domain: "bash",
	});

	assert.match(capturedText, /Bash command requires approval/i, "bash domain should show Bash");
});

test("promptPermission bash domain shows Command (not Target) for local context", async () => {
	let capturedText = "";
	const ctx: any = {
		hasUI: true,
		ui: {
			select: async (text: string) => {
				capturedText = text;
				return "4. Deny";
			},
		},
	};

	await promptPermission(ctx, {
		target: "local",
		commandPreview: "docker run --rm alpine",
		reusableUnsafe: false,
		domain: "bash",
	});

	// For bash domain, "Target" label doesn't make sense - should just show command
	// The target field should be optional or labeled differently
	assert.match(capturedText, /Command:/i, "Bash domain should show Command label");
	assert.match(capturedText, /docker run --rm alpine/, "Should show the command");
});

test("promptPermission ssh domain shows Target label", async () => {
	let capturedText = "";
	const ctx: any = {
		hasUI: true,
		ui: {
			select: async (text: string) => {
				capturedText = text;
				return "4. Deny";
			},
		},
	};

	await promptPermission(ctx, {
		target: "user@remote-host.com",
		commandPreview: "uptime",
		reusableUnsafe: false,
		domain: "ssh",
	});

	assert.match(capturedText, /Target:/i, "SSH domain should show Target label");
	assert.match(capturedText, /user@remote-host\.com/, "Should show the target");
});

test("promptPermission bash domain returns valid decisions", async () => {
	// Bash domain only has 3 options: Allow Once, Allow Session, Deny
	// No project/global option since bash approvals are never persisted
	for (const [option, expected] of [
		["1. Allow Once", "allow_once"],
		["2. Allow for this session", "allow_session"],
		["3. Deny", "deny"],
	] as const) {
		const ctx: any = {
			hasUI: true,
			ui: {
				select: async () => option,
			},
		};

		const result = await promptPermission(ctx, {
			target: "local",
			commandPreview: "echo test",
			reusableUnsafe: false,
			domain: "bash",
		});

		assert.equal(result, expected, `Option ${option} should return ${expected}`);
	}
});

test("promptPermission ssh domain returns valid decisions including project", async () => {
	// SSH domain has all 4 options
	for (const [option, expected] of [
		["1. Allow Once", "allow_once"],
		["2. Allow for this session", "allow_session"],
		["3. Allow for this Project", "allow_project"],
		["4. Deny", "deny"],
	] as const) {
		const ctx: any = {
			hasUI: true,
			ui: {
				select: async () => option,
			},
		};

		const result = await promptPermission(ctx, {
			target: "user@host",
			commandPreview: "ls -la",
			reusableUnsafe: false,
			domain: "ssh",
		});

		assert.equal(result, expected, `Option ${option} should return ${expected}`);
	}
});

test("promptPermission bash domain with reusableUnsafe shows restricted options", async () => {
	let capturedOptions: string[] = [];
	const ctx: any = {
		hasUI: true,
		ui: {
			select: async (_text: string, options: string[]) => {
				capturedOptions = options;
				return "2. Deny";
			},
		},
	};

	await promptPermission(ctx, {
		target: "local",
		commandPreview: "./custom-script.sh",
		reusableUnsafe: true,
		domain: "bash",
	});

	assert.equal(capturedOptions.length, 2, "Should have 2 options when reusableUnsafe");
	assert.ok(capturedOptions.includes("1. Allow Once"), "Should have Allow Once");
	assert.ok(capturedOptions.includes("2. Deny"), "Should have Deny");
});

// PR Issue #3: Bash domain should NOT show "Allow for this Project" option
// since bash approvals are never persisted to project/global policy
test("promptPermission bash domain hides project option (PR issue #3)", async () => {
	let capturedOptions: string[] = [];
	const ctx: any = {
		hasUI: true,
		ui: {
			select: async (_text: string, options: string[]) => {
				capturedOptions = options;
				return "2. Allow for this session"; // select session option
			},
		},
	};

	await promptPermission(ctx, {
		target: "local",
		commandPreview: "docker run --rm alpine",
		reusableUnsafe: false,
		domain: "bash",
	});

	// Bash domain should NOT show "Allow for this Project" since bash approvals
	// are session-only and never persisted to project/global policy
	assert.equal(capturedOptions.length, 3, "Bash domain should have 3 options (no project option)");
	assert.ok(capturedOptions.includes("1. Allow Once"), "Should have Allow Once");
	assert.ok(capturedOptions.includes("2. Allow for this session"), "Should have Allow for this session");
	assert.ok(capturedOptions.includes("3. Deny"), "Should have Deny (shifted to position 3)");
	assert.ok(!capturedOptions.includes("3. Allow for this Project"), "Should NOT have Allow for this Project");
	assert.ok(!capturedOptions.includes("4. Allow for this Project"), "Should NOT have Allow for this Project anywhere");
});

// Ensure SSH domain still shows all 4 options (no regression)
test("promptPermission ssh domain shows all 4 options including project", async () => {
	let capturedOptions: string[] = [];
	const ctx: any = {
		hasUI: true,
		ui: {
			select: async (_text: string, options: string[]) => {
				capturedOptions = options;
				return "4. Deny";
			},
		},
	};

	await promptPermission(ctx, {
		target: "user@host",
		commandPreview: "ls -la",
		reusableUnsafe: false,
		domain: "ssh",
	});

	assert.equal(capturedOptions.length, 4, "SSH domain should have all 4 options");
	assert.ok(capturedOptions.includes("1. Allow Once"), "Should have Allow Once");
	assert.ok(capturedOptions.includes("2. Allow for this session"), "Should have Allow for this session");
	assert.ok(capturedOptions.includes("3. Allow for this Project"), "Should have Allow for this Project");
	assert.ok(capturedOptions.includes("4. Deny"), "Should have Deny");
});
