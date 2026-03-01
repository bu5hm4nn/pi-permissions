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
	const decisions: string[] = [];

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
			target: "local",
			commandPreview: "echo test",
			reusableUnsafe: false,
			domain: "bash",
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
