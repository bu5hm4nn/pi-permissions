export type ParseCertainty = "resolved" | "uncertain";

export interface ParseShellResult {
	ast: any | null;
	certainty: ParseCertainty;
	error?: string;
}
