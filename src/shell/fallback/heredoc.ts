export function stripHeredocBodiesForLegacyParsing(command: string): string {
	const lines = command.split("\n");
	const out: string[] = [];
	let skipUntil: { delimiter: string; allowLeadingTabs: boolean } | null = null;

	for (const line of lines) {
		if (skipUntil) {
			const candidate = skipUntil.allowLeadingTabs ? line.replace(/^\t+/, "") : line;
			if (candidate.trim() === skipUntil.delimiter) {
				skipUntil = null;
			}
			continue;
		}

		out.push(line);
		const heredocMatch = line.match(/<<(-)?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/);
		if (heredocMatch) {
			skipUntil = {
				delimiter: heredocMatch[3],
				allowLeadingTabs: heredocMatch[1] === "-",
			};
		}
	}

	return out.join("\n");
}
