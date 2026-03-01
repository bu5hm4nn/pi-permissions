import { literalWordText } from "./tokens.ts";

export interface ExtractLiteralCommandNodePartsResult {
	headText: string;
	suffixLiterals: string[];
	complete: boolean;
}

export function extractLiteralCommandNodeParts(commandNode: any): ExtractLiteralCommandNodePartsResult {
	const headText = literalWordText(commandNode?.name);
	if (!headText) return { headText: "", suffixLiterals: [], complete: false };

	const suffix = Array.isArray(commandNode?.suffix) ? commandNode.suffix : [];
	const suffixLiterals: string[] = [];
	for (const part of suffix) {
		if (!part || part.type !== "Word") continue;
		const literal = literalWordText(part);
		if (!literal) return { headText: "", suffixLiterals: [], complete: false };
		suffixLiterals.push(literal);
	}

	return { headText, suffixLiterals, complete: true };
}
