/**
 * Preprocesses shell commands to strip heredoc content before parsing.
 * The bash-parser library doesn't handle heredoc content correctly (it tries to parse
 * Python/JS/etc. as shell syntax), so we need to remove the heredoc body beforehand.
 */

export interface HeredocPreprocessResult {
	/** The command with heredoc bodies stripped */
	preprocessed: string;
	/** Whether any heredocs were found and stripped */
	hasHeredocs: boolean;
	/** Number of heredocs found */
	heredocCount: number;
	/** The delimiters found (for debugging) */
	delimiters: string[];
}

/**
 * Detects and strips heredoc content from a shell command.
 *
 * Handles heredoc variants:
 *   - `<<'DELIM'` (quoted, no expansion)
 *   - `<<"DELIM"` (double-quoted, no expansion)
 *   - `<<DELIM` (unquoted, with expansion)
 *   - `<<-DELIM` (tab-stripped)
 *
 * Returns the command with the entire heredoc construct removed:
 * - The redirect operator (`<<'PY'`)
 * - The body content
 * - The closing delimiter
 *
 * This leaves only the command that accepts stdin, which can then be pattern-matched.
 */
export function preprocessHeredocs(command: string): HeredocPreprocessResult {
	const delimiters: string[] = [];

	// Pattern to find heredoc markers: <<[-]?['"]?DELIM['"]?
	// Groups: (1) = optional minus, (2) = opening quote, (3) = delimiter, (4) = closing quote
	const markerPattern = /<<(-)?[\s]*(['"]?)(\w+)\2/g;

	let match: RegExpExecArray | null;
	const foundHeredocs: Array<{ startIndex: number; endIndex: number; delim: string }> = [];

	// Reset regex state
	markerPattern.lastIndex = 0;

	while ((match = markerPattern.exec(command)) !== null) {
		const markerStart = match.index;
		const markerEnd = markerStart + match[0].length;
		const delim = match[3];
		const stripTabs = match[1] === "-";

		// Content starts after a newline following the marker
		// Find the next newline
		let searchPos = markerEnd;
		while (searchPos < command.length && command[searchPos] !== "\n") {
			searchPos++;
		}
		if (searchPos >= command.length) continue; // No newline found

		const contentStart = searchPos + 1; // Start after the newline

		// Find the line that contains just the delimiter (possibly with leading tabs for <<-)
		// Scan line by line from contentStart
		let lineStart = contentStart;
		let lineEnd = command.indexOf("\n", lineStart);
		let foundEnd = false;
		let delimLineEnd = -1;

		while (lineStart < command.length && !foundEnd) {
			if (lineEnd === -1) {
				lineEnd = command.length;
			}

			const line = command.slice(lineStart, lineEnd);

			// For <<- we strip leading tabs before comparing
			const compareLine = stripTabs ? line.replace(/^\t+/, "") : line;

			if (compareLine === delim) {
				foundEnd = true;
				// End position is end of the delimiter line (including the newline if present)
				delimLineEnd = lineEnd === command.length ? command.length : lineEnd + 1;
			} else {
				lineStart = lineEnd + 1;
				lineEnd = command.indexOf("\n", lineStart);
			}
		}

		if (foundEnd && delimLineEnd >= 0) {
			foundHeredocs.push({
				startIndex: markerStart, // Start from the `<<` so we remove the redirect too
				endIndex: delimLineEnd, // End after the delimiter line (including newline)
				delim,
			});
			delimiters.push(delim);
		}
	}

	if (foundHeredocs.length === 0) {
		return {
			preprocessed: command,
			hasHeredocs: false,
			heredocCount: 0,
			delimiters: [],
		};
	}

	// Sort by start position descending, then process from end to beginning
	// This preserves offsets as we modify the string
	foundHeredocs.sort((a, b) => b.startIndex - a.startIndex);

	let preprocessed = command;
	for (const heredoc of foundHeredocs) {
		// Remove the entire heredoc construct: marker + body + closing delimiter
		// Result: `python3 - ` (just the command before the heredoc)
		preprocessed = preprocessed.slice(0, heredoc.startIndex) + preprocessed.slice(heredoc.endIndex);
	}

	return {
		preprocessed,
		hasHeredocs: true,
		heredocCount: foundHeredocs.length,
		delimiters,
	};
}

/**
 * Strips heredoc content from a command, keeping only the outer command.
 * This allows the bash parser to work on the command structure without
 * getting confused by embedded Python/JavaScript/etc. code.
 *
 * Example:
 *   Input:  `python3 - <<'PY'\nimport json\nPY`
 *   Output: `python3 - `
 *
 * The resulting pattern would be `python3 *` since we can't analyze
 * the heredoc content, but at least we can approve the outer command.
 */
export function stripHeredocBodies(command: string): string {
	const result = preprocessHeredocs(command);
	return result.preprocessed;
}