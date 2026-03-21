import test from "node:test";
import assert from "node:assert/strict";
import {
	loadCategories,
	analyzeCommandTier,
	compareTiers,
	getHighestTier,
	getTierDefinition,
	analyzePipelineTiers,
	resetCategoriesCache,
} from "../src/policy/command-categories.ts";

test("loads categories without error", () => {
	const cats = loadCategories();
	assert.ok(cats.version);
	assert.ok(cats.tier_definitions);
	assert.ok(cats.commands);
});

test("getTierDefinition returns metadata", () => {
	const readonlyDef = getTierDefinition("readonly");
	assert.equal(readonlyDef.risk_level, 1);
	assert.equal(readonlyDef.auto_approve, false);

	const deleteDef = getTierDefinition("delete");
	assert.equal(deleteDef.risk_level, 6);
});

test("compareTiers orders by risk level", () => {
	assert.ok(compareTiers("readonly", "delete") < 0);
	assert.ok(compareTiers("delete", "readonly") > 0);
	assert.ok(compareTiers("edit", "edit") === 0);
	assert.ok(compareTiers("readonly", "unknown") < 0);
});

test("getHighestTier returns most dangerous", () => {
	assert.equal(getHighestTier(["readonly", "delete", "status"]), "delete");
	assert.equal(getHighestTier(["readonly", "status"]), "status");
	assert.equal(getHighestTier([]), "unknown");
});

test("analyzeCommandTier returns readonly for pwd", () => {
	const result = analyzeCommandTier("pwd");
	assert.equal(result.tier, "readonly");
});

test("analyzeCommandTier returns readonly for ls-like commands", () => {
	assert.equal(analyzeCommandTier("whoami").tier, "readonly");
	assert.equal(analyzeCommandTier("hostname").tier, "readonly");
	assert.equal(analyzeCommandTier("true").tier, "readonly");
	assert.equal(analyzeCommandTier("false").tier, "readonly");
});

test("analyzeCommandTier returns readonly for cat", () => {
	assert.equal(analyzeCommandTier("cat").tier, "readonly");
	assert.equal(analyzeCommandTier("head").tier, "readonly");
	assert.equal(analyzeCommandTier("tail").tier, "readonly");
	assert.equal(analyzeCommandTier("grep").tier, "readonly");
	assert.equal(analyzeCommandTier("find").tier, "readonly");
});

test("analyzeCommandTier escalates sed -i to edit", () => {
	const readonlyResult = analyzeCommandTier("sed", ["-n", "1,10p"]);
	assert.equal(readonlyResult.tier, "readonly");

	const editResult = analyzeCommandTier("sed", ["-i", "s/old/new/"]);
	assert.equal(editResult.tier, "edit");
});

test("analyzeCommandTier escalates find -delete to delete", () => {
	const readonlyResult = analyzeCommandTier("find", [".", "-name", "*.log"]);
	assert.equal(readonlyResult.tier, "readonly");

	const deleteResult = analyzeCommandTier("find", [".", "-name", "*.log", "-delete"]);
	assert.equal(deleteResult.tier, "delete");
});

test("analyzeCommandTier handles subcommands", () => {
	assert.equal(analyzeCommandTier("docker", ["ps"]).tier, "status");
	assert.equal(analyzeCommandTier("docker", ["logs", "container"]).tier, "status");
	assert.equal(analyzeCommandTier("docker", ["run", "image"]).tier, "create");
	assert.equal(analyzeCommandTier("docker", ["rm", "container"]).tier, "delete");

	assert.equal(analyzeCommandTier("kubectl", ["get", "pods"]).tier, "status");
	assert.equal(analyzeCommandTier("kubectl", ["delete", "pod"]).tier, "delete");

	assert.equal(analyzeCommandTier("git", ["status"]).tier, "status");
	assert.equal(analyzeCommandTier("git", ["log"]).tier, "readonly");
	assert.equal(analyzeCommandTier("git", ["commit"]).tier, "edit");
	assert.equal(analyzeCommandTier("git", ["push"]).tier, "network");
});

test("analyzeCommandTier returns delete for rm", () => {
	assert.equal(analyzeCommandTier("rm").tier, "delete");
	assert.equal(analyzeCommandTier("rmdir").tier, "delete");
});

test("analyzeCommandTier returns create for mkdir/touch", () => {
	assert.equal(analyzeCommandTier("mkdir").tier, "create");
	assert.equal(analyzeCommandTier("touch").tier, "create");
	assert.equal(analyzeCommandTier("cp").tier, "create");
});

test("analyzeCommandTier returns edit for vim/nano", () => {
	assert.equal(analyzeCommandTier("vim").tier, "edit");
	assert.equal(analyzeCommandTier("nano").tier, "edit");
});

test("analyzeCommandTier returns privileged for sudo", () => {
	assert.equal(analyzeCommandTier("sudo").tier, "privileged");
	assert.equal(analyzeCommandTier("su").tier, "privileged");
	assert.equal(analyzeCommandTier("doas").tier, "privileged");
});

test("analyzeCommandTier returns network for curl/wget", () => {
	assert.equal(analyzeCommandTier("curl").tier, "network");
	assert.equal(analyzeCommandTier("wget").tier, "network");
});

test("analyzeCommandTier returns unknown for uncategorized commands", () => {
	assert.equal(analyzeCommandTier("someunknowncommand").tier, "unknown");
});

test("analyzeCommandTier handles systemctl subcommands", () => {
	assert.equal(analyzeCommandTier("systemctl", ["status", "nginx"]).tier, "status");
	assert.equal(analyzeCommandTier("systemctl", ["restart", "nginx"]).tier, "restart");
	assert.equal(analyzeCommandTier("systemctl", ["enable", "nginx"]).tier, "edit");
	assert.equal(analyzeCommandTier("systemctl", ["mask", "nginx"]).tier, "delete");
});

test("analyzeCommandTier handles docker with flags", () => {
	// -d flag should not change tier
	const runResult = analyzeCommandTier("docker", ["run", "-d", "image"]);
	assert.equal(runResult.tier, "create");
});

test("analyzePipelineTiers returns highest tier from pipeline", () => {
	const { tier, tiers } = analyzePipelineTiers([
		{ executable: "cat", args: ["file"] },
		{ executable: "grep", args: ["pattern"] },
		{ executable: "wc", args: ["-l"] },
	]);
	assert.deepEqual(tiers, ["readonly", "readonly", "readonly"]);
	assert.equal(tier, "readonly");
});

test("analyzePipelineTiers escalates when any command is dangerous", () => {
	const { tier, tiers } = analyzePipelineTiers([
		{ executable: "cat", args: ["file"] },
		{ executable: "rm", args: ["file"] },
	]);
	assert.deepEqual(tiers, ["readonly", "delete"]);
	assert.equal(tier, "delete");
});

test("analyzePipelineTiers handles mixed tier pipeline", () => {
	const { tier } = analyzePipelineTiers([
		{ executable: "git", args: ["status"] }, // status
		{ executable: "sed", args: ["-i", "s/old/new/"] }, // edit
		{ executable: "cat", args: ["file"] }, // readonly
	]);
	assert.equal(tier, "edit");
});