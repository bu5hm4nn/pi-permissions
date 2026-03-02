import test from "node:test";
import assert from "node:assert/strict";
import { formatAllowPatternSummary } from "../src/policy/command-patterns.ts";
import { promptPermission } from "../src/ui/prompt.ts";

test("promptPermission select text includes wget summary example", async () => {
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
		target: "dev@example.com",
		commandPreview: "wget --post-data='x=1' https://api.example.com/items",
		reusableUnsafe: false,
		missingPatternSummary: formatAllowPatternSummary(["wget POST *"]),
	});

	assert.match(capturedText, /wget --post-data=\.\.\. https:\/\/api\.example\.com\/\.\.\./);
});

test("promptPermission select text includes URL-scoped pattern summary example", async () => {
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
		target: "dev@example.com",
		commandPreview: "curl -X DELETE https://api.admin.org/items/1",
		reusableUnsafe: false,
		missingPatternSummary: formatAllowPatternSummary(["curl DELETE https://api.admin.org/*"]),
	});

	assert.match(capturedText, /curl -X DELETE https:\/\/api\.admin\.org\/\.\.\./);
});
