import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { isDirectSshFamilyCommand as analyzerDirectSsh } from "../src/shell/analyzers/direct-ssh.ts";
import { analyzeCommandPatterns as analyzerCommandPatterns } from "../src/shell/analyzers/command-patterns.ts";
import { isDirectSshFamilyCommand as adapterDirectSsh } from "../src/ssh/matcher.ts";
import { analyzeCommandPatterns as adapterCommandPatterns } from "../src/policy/command-patterns.ts";

interface CorpusCase {
	name: string;
	command: string;
	expect: {
		matcherBlocked: boolean;
		patternsComplete: boolean;
		patterns?: string[];
	};
}

async function loadCorpus(): Promise<CorpusCase[]> {
	const raw = await readFile(new URL("./corpus/cross-analyzer.json", import.meta.url), "utf-8");
	return JSON.parse(raw) as CorpusCase[];
}

test("cross-analyzer corpus preserves expected and adapter-parity behavior", async () => {
	const corpus = await loadCorpus();
	assert.ok(corpus.length > 0, "corpus must contain cases");

	for (const row of corpus) {
		const analyzerBlocked = analyzerDirectSsh(row.command);
		const adapterBlocked = adapterDirectSsh(row.command);
		assert.equal(adapterBlocked, analyzerBlocked, `${row.name}: matcher adapter drift`);
		assert.equal(analyzerBlocked, row.expect.matcherBlocked, `${row.name}: matcher expectation drift`);

		const analyzerPatterns = analyzerCommandPatterns(row.command);
		const adapterPatterns = adapterCommandPatterns(row.command);
		assert.equal(adapterPatterns.complete, analyzerPatterns.complete, `${row.name}: pattern adapter complete drift`);
		assert.equal(adapterPatterns.reason, analyzerPatterns.reason, `${row.name}: pattern adapter reason drift`);
		assert.deepEqual(new Set(adapterPatterns.patterns), new Set(analyzerPatterns.patterns), `${row.name}: pattern adapter drift`);
		assert.equal(analyzerPatterns.complete, row.expect.patternsComplete, `${row.name}: patterns complete drift`);
		if (row.expect.patterns) {
			assert.deepEqual(new Set(analyzerPatterns.patterns), new Set(row.expect.patterns), `${row.name}: patterns drift`);
		}
	}
});
