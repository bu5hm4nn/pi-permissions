/**
 * Command categorization system for intelligent pattern matching
 * and tiered approval policies.
 *
 * Tiers (from lowest to highest risk):
 *   1. readonly   - No side effects
 *   2. status     - Read system state
 *   3. restart    - Service restart
 *   4. edit       - Modify existing files
 *   5. create     - Create new resources
 *   6. delete     - Destructive operations
 *   7. network    - Network operations
 *   8. privileged - Privilege escalation
 *   9. unknown    - Requires full review
 */

import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as yaml from "yaml";

export type CommandTier =
	| "readonly"
	| "status"
	| "restart"
	| "edit"
	| "create"
	| "delete"
	| "network"
	| "privileged"
	| "unknown";

export interface TierDefinition {
	description: string;
	risk_level: number;
	auto_approve: boolean;
}

export interface CommandDefinition {
	tier: CommandTier;
	patterns?: string[];
	subcommands?: Record<string, CommandDefinition>;
	flags?: Record<string, { tier?: CommandTier; note?: string }>;
	note?: string;
}

export interface CategoryDefinitions {
	version: number;
	tier_definitions: Record<CommandTier, TierDefinition>;
	commands: Record<string, CommandDefinition>;
}

let categories: CategoryDefinitions | null = null;

/**
 * Load command categories from YAML definition.
 * Caches the result for subsequent calls.
 */
export function loadCategories(): CategoryDefinitions {
	if (categories) return categories;

	const currentDir = dirname(fileURLToPath(import.meta.url));
	const yamlPath = join(currentDir, "command-categories.yaml");

	if (!existsSync(yamlPath)) {
		throw new Error(`Command categories file not found: ${yamlPath}`);
	}

	const content = readFileSync(yamlPath, "utf-8");
	categories = yaml.parse(content) as CategoryDefinitions;

	return categories;
}

/**
 * Get tier metadata for a tier name.
 */
export function getTierDefinition(tier: CommandTier): TierDefinition {
	const defs = loadCategories();
	return defs.tier_definitions[tier];
}

/**
 * Compare two tiers by risk level.
 * Returns: negative if a < b, positive if a > b, 0 if equal
 */
export function compareTiers(a: CommandTier, b: CommandTier): number {
	const defs = loadCategories();
	const levelA = defs.tier_definitions[a]?.risk_level ?? 999;
	const levelB = defs.tier_definitions[b]?.risk_level ?? 999;
	return levelA - levelB;
}

/**
 * Get the highest (most dangerous) tier from a list.
 */
export function getHighestTier(tiers: CommandTier[]): CommandTier {
	if (tiers.length === 0) return "unknown";
	return tiers.reduce((max, tier) =>
		compareTiers(tier, max) > 0 ? tier : max,
	tiers[0]);
}

/**
 * Analyze a command and determine its tier.
 * This is a simplified analysis - full analysis uses the pattern matcher.
 */
export function analyzeCommandTier(
	executable: string,
	args: string[] = [],
): { tier: CommandTier; definition?: CommandDefinition; note?: string } {
	const defs = loadCategories();
	const cmd = executable.toLowerCase();

	// Check if command is defined
	const cmdDef = defs.commands[cmd];
	if (!cmdDef) {
		return { tier: "unknown" };
	}

	// Check for subcommands (for tools like docker, kubectl, git)
	if (cmdDef.subcommands && args.length > 0) {
		// Find the subcommand (skip flags)
		let subcmdIndex = 0;
		while (subcmdIndex < args.length && args[subcmdIndex].startsWith("-")) {
			subcmdIndex++;
		}

		if (subcmdIndex < args.length) {
			const subcmd = args[subcmdIndex];
			const subDef = cmdDef.subcommands[subcmd];

			if (subDef) {
				// Check for flag-based tier escalation
				const flagTier = checkFlagTier(cmdDef, args);
				if (flagTier && compareTiers(flagTier, subDef.tier) > 0) {
					return { tier: flagTier, definition: subDef };
				}
				return { tier: subDef.tier, definition: subDef, note: subDef.note };
			}
		}
	}

	// Check for flag-based tier escalation
	const flagTier = checkFlagTier(cmdDef, args);
	if (flagTier && compareTiers(flagTier, cmdDef.tier) > 0) {
		return { tier: flagTier, definition: cmdDef };
	}

	return { tier: cmdDef.tier, definition: cmdDef, note: cmdDef.note };
}

/**
 * Check if any flags escalate the tier.
 */
function checkFlagTier(cmdDef: CommandDefinition, args: string[]): CommandTier | null {
	if (!cmdDef.flags) return null;

	for (const arg of args) {
		// Handle --flag=value form
		const flagBase = arg.includes("=") ? arg.split("=")[0] : arg;

		// Check exact match first
		const flagDef = cmdDef.flags[flagBase];
		if (flagDef?.tier) {
			return flagDef.tier;
		}

		// Also check short flags embedded in cluster (e.g., -ia for -i -a)
		if (arg.startsWith("-") && !arg.startsWith("--")) {
			for (const char of arg.slice(1)) {
				const shortFlag = `-${char}`;
				const shortDef = cmdDef.flags[shortFlag];
				if (shortDef?.tier) {
					return shortDef.tier;
				}
			}
		}
	}

	return null;
}

/**
 * Get all patterns for a command.
 */
export function getCommandPatterns(executable: string): string[] {
	const defs = loadCategories();
	const cmd = executable.toLowerCase();
	const cmdDef = defs.commands[cmd];

	if (!cmdDef) return [];

	const patterns: string[] = cmdDef.patterns ?? [];

	// Add subcommand patterns
	if (cmdDef.subcommands) {
		for (const [subcmd, subDef] of Object.entries(cmdDef.subcommands)) {
			if (subDef.patterns) {
				patterns.push(...subDef.patterns);
			}
		}
	}

	return patterns;
}

/**
 * Check if a command has special handling requirements.
 */
export function getCommandNotes(executable: string): string[] {
	const defs = loadCategories();
	const cmd = executable.toLowerCase();
	const cmdDef = defs.commands[cmd];

	if (!cmdDef) return [];

	const notes: string[] = [];
	if (cmdDef.note) notes.push(cmdDef.note);
	if (cmdDef.subcommands) {
		for (const subDef of Object.values(cmdDef.subcommands)) {
			if (subDef.note) notes.push(subDef.note);
		}
	}
	if (cmdDef.flags) {
		for (const flagDef of Object.values(cmdDef.flags)) {
			if (flagDef.note) notes.push(flagDef.note);
		}
	}

	return notes;
}

/**
 * Analyze a pipeline of commands and return the highest tier.
 * When commands are piped together, the highest risk tier wins.
 */
export function analyzePipelineTiers(
	commands: Array<{ executable: string; args: string[] }>,
): { tier: CommandTier; tiers: CommandTier[] } {
	const tiers = commands.map((cmd) => analyzeCommandTier(cmd.executable, cmd.args).tier);
	const highest = getHighestTier(tiers);
	return { tier: highest, tiers };
}

/**
 * Reset the categories cache (for testing).
 */
export function resetCategoriesCache(): void {
	categories = null;
}