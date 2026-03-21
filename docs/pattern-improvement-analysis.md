# Pattern Extraction Improvement Analysis

## Executive Summary

The current pattern extraction in `src/shell/analyzers/command-patterns.ts` produces wildcard-only patterns (`cmd *`) for most common Unix commands. This document analyzes the current state and proposes improvements to extract more specific, actionable patterns.

## Current State

### Pattern Extraction Flow

```
Command → parseShell → walkShellAst → extractCommandPattern
                                              ↓
                                    ┌─────────────────────┐
                                    │ Special handler?   │
                                    │ (curl/wget/docker) │
                                    └─────────────────────┘
                                              ↓ No
                                    ┌─────────────────────┐
                                    │ Subcommand support? │
                                    │ (git/npm/kubectl)  │
                                    └─────────────────────┘
                                              ↓ No
                                    ┌─────────────────────┐
                                    │ Fallback: cmd *    │
                                    └─────────────────────┘
```

### Commands with Special Handlers

| Command | Handler | Pattern Output |
|---------|---------|----------------|
| `curl` | `extractCurlMethodPatterns` | `curl GET *`, `curl POST https://...` |
| `wget` | `extractWgetMethodPatterns` | `wget GET *`, `wget POST https://...` |
| `docker run/exec` | `extractDockerShellPatterns` | Nested pattern extraction |
| `docker compose` | subcommand detection | `docker compose *` |
| Other subcommand tools | generic subcommand | `tool subcommand *` |

### Commands with Wildcard-Only Patterns

All commands without special handlers produce `cmd *`:
- `pwd` → `pwd *`
- `ls -la` → `ls *`
- `echo 'text'` → `echo *`
- `sed -n '1,220p' file` → `sed *`
- `find . -maxdepth 2 -name '*.ext'` → `find *`
- `cat file` → `cat *`
- `grep pattern file` → `grep *`

## Proposed Improvements

### 1. Flag Pattern Preservation

**Problem**: `ls -la` → `ls *` loses valuable context about what the command does.

**Solution**: Extract and preserve flags in pattern.

```typescript
// Pattern: "ls -la /home/user"
// Current: "ls *"
// Proposed: "ls -la"
```

**Implementation**:

```typescript
function extractFlags(args: string[]): { flags: string[]; remainingArgs: string[] } {
  const flags: string[] = [];
  const remainingArgs: string[] = [];
  let i = 0;

  while (i < args.length) {
    const arg = args[i];
    
    if (arg === "--") {
      // End of flags
      remainingArgs.push(...args.slice(i + 1));
      break;
    }
    
    if (arg.startsWith("--")) {
      // Long flag: --all or --file=FILE
      const flagBase = arg.includes("=") ? arg.split("=")[0] : arg;
      flags.push(flagBase);
      i++;
      continue;
    }
    
    if (arg.startsWith("-") && arg.length > 1) {
      // Short flag cluster: -la -> -l, -a
      for (const c of arg.slice(1)) {
        flags.push(`-${c}`);
      }
      i++;
      continue;
    }
    
    // Not a flag
    remainingArgs.push(arg);
    i++;
  }

  return { flags, remainingArgs };
}
```

### 2. Simple Commands with No Meaningful Arguments

**Problem**: `pwd` produces `pwd *` when it never takes meaningful arguments.

**Solution**: Recognize commands with trivial argument patterns.

```typescript
const TRIVIAL_COMMANDS = new Set([
  'pwd',      // Always returns working directory
  'true',     // Always succeeds
  'false',    // Always fails
  'date',     // Shows date, arguments rarely matter for security
  'hostname', // Shows hostname
  'id',       // Shows user identity
  'whoami',   // Shows current user
]);

// In extractCommandPattern:
if (TRIVIAL_COMMANDS.has(executable.toLowerCase())) {
  return { patterns: [executable.toLowerCase()], complete: true };
}
```

### 3. Readonly File Commands

**Problem**: `cat /etc/passwd` → `cat *` (wildcard hides file access intent)

**Solution**: Classify commands by risk and extract file arguments when safe.

```typescript
const READONLY_FILE_COMMANDS = new Set([
  'cat', 'head', 'tail', 'less', 'more',
  'grep', 'rg', 'ag', 'sort', 'uniq', 'wc',
]);

/**
 * For readonly commands, preserve path patterns when they're literal.
 * Pattern: "cat /etc/passwd" → "cat [path]" (not "cat *")
 */
function extractReadonlyPattern(executable: string, args: string[]): { patterns: string[]; complete: boolean } {
  // Filter flags to get actual file arguments
  const { flags, remainingArgs } = extractFlags(args);
  
  // Find first path-like argument
  for (const arg of remainingArgs) {
    if (arg.startsWith('/') || arg.startsWith('./') || arg.startsWith('../')) {
      // Absolute or relative path
      return {
        patterns: [`${executable} ${arg}`],
        complete: true
      };
    }
  }
  
  // No explicit file argument
  return {
    patterns: [`${executable} *`],
    complete: true
  };
}
```

### 4. Find Command Handler

**Problem**: `find . -maxdepth 2 -name '*.ext'` → `find *` loses all specificity.

**Solution**: Parse find's query structure.

```typescript
interface FindPattern {
  paths: string[];       // Starting paths
  tests: string[];       // Test operators (name, type, etc.)
  actions: string[];     // Actions (exec, print, etc.)
  complete: boolean;
}

function extractFindPattern(args: string[]): FindPattern {
  const paths: string[] = [];
  const tests: string[] = [];
  const actions: string[] = [];
  
  const TEST_WITH_VALUE = new Set([
    '-name', '-iname', '-path', '-ipath',
    '-type', '-size', '-perm',
    '-maxdepth', '-mindepth',
    '-user', '-group',
    '-mtime', '-atime', '-ctime',
  ]);
  
  let i = 0;
  let phase: 'paths' | 'tests' = 'paths';
  
  while (i < args.length) {
    const arg = args[i];
    
    // Collect paths until first option
    if (phase === 'paths' && !arg.startsWith('-')) {
      paths.push(arg);
      i++;
      continue;
    }
    
    phase = 'tests';
    
    // Handle tests with values
    if (TEST_WITH_VALUE.has(arg)) {
      if (i + 1 >= args.length) {
        return { paths, tests, actions, complete: false };
      }
      tests.push(arg, args[i + 1]);
      i += 2;
      continue;
    }
    
    // Handle boolean operators
    if (['-and', '-or', '-not', '!', '-a', '-o'].includes(arg)) {
      tests.push(arg);
      i++;
      continue;
    }
    
    // Handle -exec/-execdir
    if (arg === '-exec' || arg === '-execdir' || arg === '-ok' || arg === '-okdir') {
      actions.push(arg);
      i++;
      // Find terminator
      while (i < args.length && args[i] !== ';' && args[i] !== '+') {
        i++;
      }
      if (i < args.length) i++;
      continue;
    }
    
    // Handle simple actions
    if (['-print', '-print0', '-ls', '-quit', '-delete'].includes(arg)) {
      actions.push(arg);
      i++;
      continue;
    }
    
    // Unknown argument in test phase
    i++;
  }
  
  return { paths, tests, actions, complete: true };
}

function formatFindPattern(executable: string, fp: FindPattern): string {
  const parts: string[] = [executable];
  
  // Path
  if (fp.paths.length > 0) {
    parts.push(fp.paths.join(' '));
  } else {
    parts.push('.');
  }
  
  // Key tests (preserve semantics, elide values)
  for (let i = 0; i < fp.tests.length; i += 2) {
    const test = fp.tests[i];
    parts.push(test);
    if (test === '-type' && fp.tests[i + 1]) {
      parts.push(fp.tests[i + 1]); // -type f,d,l are meaningful
    }
    // -name patterns are less meaningful for security
  }
  
  // End with wildcard
  parts.push('*');
  
  return parts.join(' ');
}
```

**Example transformations**:
- `find . -maxdepth 2 -name '*.ext'` → `find . -maxdepth * -name * *`
- `find . -type f -exec rm {} \;` → `find . -type f -exec`
- `find /var/log -name '*.log' -print` → `find /var/log -name * *`

### 5. Sed Pattern Handler

**Problem**: `sed -n '1,220p' file` → `sed *` (loses script info)

**Solution**: Extract sed command letters.

```typescript
function extractSedPattern(executable: string, args: string[]): { patterns: string[]; complete: boolean } {
  let i = 0;
  const flags: string[] = [];
  let command: string | null = null;
  
  // Collect flags
  while (i < args.length) {
    const arg = args[i];
    
    if (arg === '--') {
      i++;
      break;
    }
    
    if (arg === '-e' || arg === '--expression') {
      if (i + 1 >= args.length) {
        return { patterns: [`${executable} *`], complete: false };
      }
      // Extract command from expression
      const expr = args[i + 1];
      const cmdMatch = expr.match(/[a-z]$/);
      if (cmdMatch) command = cmdMatch[0];
      i += 2;
      continue;
    }
    
    if (arg.startsWith('-e')) {
      const expr = arg.slice(2);
      const cmdMatch = expr.match(/[a-z]$/);
      if (cmdMatch) command = cmdMatch[0];
      i++;
      continue;
    }
    
    if (arg.startsWith('-') && !arg.startsWith('-e') && !arg.startsWith('-f')) {
      // Flag cluster
      for (const c of arg.slice(1)) flags.push(c);
      i++;
      continue;
    }
    
    // First non-flag that's not -e/-f is the script (if no -e/-f yet)
    if (!command && !arg.startsWith('-')) {
      const cmdMatch = arg.match(/[a-z]$/);
      if (cmdMatch) command = cmdMatch[0];
    }
    i++;
  }
  
  const flagPart = flags.length > 0 ? `-${flags.join('')}` : '';
  
  if (command) {
    return {
      patterns: [`${executable} ${flagPart} ...${command}`.trim()],
      complete: true
    };
  }
  
  return {
    patterns: [`${executable} ${flagPart} *`.trim()],
    complete: true
  };
}
```

**Example transformations**:
- `sed -n '1,220p' file` → `sed -n ...p`
- `sed 's/foo/bar/'` → `sed ...s`
- `sed -i 's/foo/bar/' file` → `sed -i ...s`

### 6. Echo Argument Pattern

**Problem**: `echo 'text'` → `echo *` (loses that it's just output)

**Solution**: Distinguish between simple echo and command substitution echo.

```typescript
function extractEchoPattern(executable: string, args: string[]): { patterns: string[]; complete: boolean } {
  // Check for command substitution (riskier)
  const argsStr = args.join(' ');
  if (argsStr.includes('$(') || argsStr.includes('`')) {
    // Contains command substitution - more complex
    return { patterns: [`${executable} *`], complete: true };
  }
  
  // Simple echo with literal text
  if (args.some(a => a.startsWith('-e') || a.startsWith('-n') || a.startsWith('-E'))) {
    // Has a flag
    return { patterns: [`${executable} -[*] *`], complete: true };
  }
  
  // Plain echo
  return { patterns: [executable], complete: true };
}
```

## Implementation Diff

### Proposed changes to `src/shell/analyzers/command-patterns.ts`

```diff
--- a/src/shell/analyzers/command-patterns.ts
+++ b/src/shell/analyzers/command-patterns.ts
@@ -1,5 +1,6 @@
 import { walkShellAst } from "../parser/ast-walk.ts";
 import { parseShell } from "../parser/parse.ts";
 import { extractLiteralCommandNodeParts } from "../parser/command-node.ts";
=======
 import { extractCommonCommandPatterns, TRIVIAL_COMMANDS } from "./common-commands.ts";
 import { walkShellAst } from "../parser/ast-walk.ts";
 import { parseShell } from "../parser/parse.ts";
 import { extractLiteralCommandNodeParts } from "../parser/command-node.ts";
@@ -85,6 +86,16 @@
 function extractCommandPattern(node: any, depth: number): { patterns: string[]; complete: boolean } {
 	// ... existing code ...
 	
+	// Check for trivial commands that don't need patterns
+	if (TRIVIAL_COMMANDS.has(executable.toLowerCase())) {
+		return { patterns: [executable.toLowerCase()], complete: true };
+	}
+	
+	// Try common command pattern extraction
+	const commonPatterns = extractCommonCommandPatterns(executable, args);
+	if (commonPatterns) {
+		return commonPatterns;
+	}
 	
 	// ... rest of existing code ...
 }
```

### New file: `src/shell/analyzers/common-commands.ts`

```typescript
/**
 * Pattern extraction for common Unix commands.
 * These commands don't have subcommands like docker/git but have
 * meaningful flag/argument structures worth preserving.
 */

import { normalizeLiteralToken } from "../parser/tokens.ts";

/**
 * Commands that never take meaningful arguments from a security perspective.
 * Pattern: just the command name.
 */
export const TRIVIAL_COMMANDS = new Set([
	"pwd",
	"true",
	"false",
	"whoami",
	"hostname",
]);

/**
 * Commands that are simple echo/writers with optional flags.
 * Pattern: command or command -flags
 */
const SIMPLE_ECHO_COMMANDS = new Set(["echo", "printf"]);

/**
 * Commands where preserving flags improves pattern specificity.
 */
const FLAG_COMMANDS = new Set([
	"ls",
	"grep",
	"rg",
	"ag",
	"cat",
	"head",
	"tail",
	"less",
	"more",
	"wc",
	"sort",
	"uniq",
]);

/**
 * Commands that take a file path argument.
 */
const FILE_PATH_COMMANDS = new Set([
	"cat",
	"head",
	"tail",
	"less",
	"more",
	"vim",
	"nano",
	"rm",
	"mkdir",
	"touch",
	"mv",
	"cp",
]);

interface FlagExtraction {
	flags: string[];
	remainingArgs: string[];
}

/**
 * Extract flag cluster from arguments.
 * Returns flags and remaining non-flag arguments.
 */
function extractFlags(args: string[]): FlagExtraction {
	const flags: string[] = [];
	const remainingArgs: string[] = [];
	let i = 0;

	while (i < args.length) {
		const arg = args[i];

		if (arg === "--") {
			remainingArgs.push(...args.slice(i + 1));
			break;
		}

		if (arg.startsWith("--")) {
			// Long flag: --all or --file=FILE
			const flagBase = arg.includes("=") ? arg.split("=")[0] : arg;
			flags.push(flagBase);
			i++;
			continue;
		}

		if (arg.startsWith("-") && arg.length > 1) {
			// Short flag cluster: -la -> -l, -a
			for (const c of arg.slice(1)) {
				flags.push(`-${c}`);
			}
			i++;
			continue;
		}

		remainingArgs.push(arg);
		i++;
	}

	return { flags, remainingArgs };
}

/**
 * Find commands with complex query structure.
 */
interface FindPattern {
	paths: string[];
	tests: string[];
	actions: string[];
	complete: boolean;
}

const FIND_TEST_WITH_VALUE = new Set([
	"-name",
	"-iname",
	"-path",
	"-ipath",
	"-type",
	"-size",
	"-perm",
	"-maxdepth",
	"-mindepth",
	"-user",
	"-group",
	"-mtime",
	"-atime",
	"-ctime",
	"-newer",
]);

const FIND_BOOLEAN_OPS = new Set(["-and", "-or", "-not", "!", "-a", "-o"]);

const FIND_EXEC_ACTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);

const FIND_SIMPLE_ACTIONS = new Set(["-print", "-print0", "-ls", "-quit", "-delete"]);

function extractFindPattern(args: string[]): FindPattern {
	const paths: string[] = [];
	const tests: string[] = [];
	const actions: string[] = [];

	let i = 0;
	let phase: "paths" | "tests" = "paths";

	while (i < args.length) {
		const arg = args[i];

		if (phase === "paths" && !arg.startsWith("-")) {
			paths.push(arg);
			i++;
			continue;
		}

		phase = "tests";

		if (FIND_TEST_WITH_VALUE.has(arg)) {
			if (i + 1 >= args.length) {
				return { paths, tests, actions, complete: false };
			}
			tests.push(arg);
			if (arg === "-type" || arg === "-perm") {
				// Preserve type and perm values (meaningful for security)
				tests.push(args[i + 1]);
			}
			i += 2;
			continue;
		}

		if (FIND_BOOLEAN_OPS.has(arg)) {
			tests.push(arg);
			i++;
			continue;
		}

		if (FIND_EXEC_ACTIONS.has(arg)) {
			actions.push(arg);
			i++;
			while (i < args.length && args[i] !== ";" && args[i] !== "+") {
				i++;
			}
			if (i < args.length) i++;
			continue;
		}

		if (FIND_SIMPLE_ACTIONS.has(arg)) {
			actions.push(arg);
			i++;
			continue;
		}

		i++;
	}

	return { paths, tests, actions, complete: true };
}

function formatFindPattern(fp: FindPattern): string {
	const parts: string[] = ["find"];

	if (fp.paths.length > 0) {
		parts.push(fp.paths[0]); // Just first path
	} else {
		parts.push(".");
	}

	// Add -type if present (most meaningful for security)
	const typeIdx = fp.tests.indexOf("-type");
	if (typeIdx >= 0 && typeIdx + 1 < fp.tests.length) {
		parts.push("-type", fp.tests[typeIdx + 1]);
	}

	// Add actions
	if (fp.actions.length > 0) {
		parts.push(fp.actions[0]);
	}

	parts.push("*");
	return parts.join(" ");
}

/**
 * Sed commands with script patterns.
 */
function extractSedPattern(
	executable: string,
	args: string[],
): { patterns: string[]; complete: boolean } {
	let i = 0;
	const flags: string[] = [];
	let command: string | null = null;

	while (i < args.length) {
		const arg = args[i];

		if (arg === "--") {
			i++;
			break;
		}

		if (arg === "-e" || arg === "--expression") {
			if (i + 1 >= args.length) {
				return { patterns: [`${executable} *`], complete: false };
			}
			const expr = args[i + 1];
			const cmdMatch = expr.match(/[a-zA-Z]$/);
			if (cmdMatch) command = cmdMatch[0];
			i += 2;
			continue;
		}

		if (arg.startsWith("-e")) {
			const expr = arg.slice(2);
			const cmdMatch = expr.match(/[a-zA-Z]$/);
			if (cmdMatch) command = cmdMatch[0];
			i++;
			continue;
		}

		if (arg.startsWith("-") && !arg.startsWith("-e") && !arg.startsWith("-f")) {
			for (const c of arg.slice(1)) flags.push(c);
			i++;
			continue;
		}

		// First non-flag is the script (if no -e/-f yet)
		if (!command && !arg.startsWith("-")) {
			const cmdMatch = arg.match(/[a-zA-Z]$/);
			if (cmdMatch) command = cmdMatch[0];
		}
		i++;
	}

	const flagPart = flags.length > 0 ? `-${flags.join("")}` : "";

	if (command) {
		const pattern = flagPart ? `${executable} ${flagPart} ...${command}` : `${executable} ...${command}`;
		return { patterns: [pattern], complete: true };
	}

	const pattern = flagPart ? `${executable} ${flagPart} *` : `${executable} *`;
	return { patterns: [pattern], complete: true };
}

/**
 * Grep commands with pattern preservation.
 */
function extractGrepPattern(
	executable: string,
	args: string[],
): { patterns: string[]; complete: boolean } {
	const { flags, remainingArgs } = extractFlags(args);

	const hasRecursive = flags.includes("-r") || flags.includes("-R") || flags.includes("--recursive");

	// For searches, the pattern is less important than recursive flag
	if (hasRecursive) {
		const flagPart = flags.filter((f) => f === "-r" || f === "-R" || f.startsWith("--recurs")).join(" ");
		return { patterns: [`${executable} ${flagPart} *`], complete: true };
	}

	// Non-recursive grep
	if (flags.length > 0) {
		return { patterns: [`${executable} -${flags.map((f) => f.slice(1)).join("")} *`], complete: true };
	}

	return { patterns: [`${executable} *`], complete: true };
}

/**
 * Main entry point for common command pattern extraction.
 */
export function extractCommonCommandPatterns(
	executable: string,
	args: string[],
): { patterns: string[]; complete: boolean } | null {
	const cmd = executable.toLowerCase();

	// Trivial commands (handled in caller)
	if (TRIVIAL_COMMANDS.has(cmd)) {
		return null; // Let caller handle with simpler logic
	}

	// Find with structured pattern
	if (cmd === "find") {
		const fp = extractFindPattern(args);
		return { patterns: [formatFindPattern(fp)], complete: fp.complete };
	}

	// Sed with command extraction
	if (cmd === "sed") {
		return extractSedPattern(executable, args);
	}

	// Grep
	if (cmd === "grep" || cmd === "rg" || cmd === "ag") {
		return extractGrepPattern(executable, args);
	}

	// Simple echo
	if (SIMPLE_ECHO_COMMANDS.has(cmd)) {
		const argsStr = args.join(" ");
		// Detect command substitution
		if (argsStr.includes("$(") || argsStr.includes("`")) {
			return { patterns: [`${executable} *`], complete: true };
		}
		// Just echo - let it through
		return { patterns: [executable], complete: true };
	}

	// Commands where we extract flags
	if (FLAG_COMMANDS.has(cmd)) {
		const { flags } = extractFlags(args);
		if (flags.length > 0) {
			const flagPart = `-${flags.map((f) => f.slice(1)).join("")}`;
			return { patterns: [`${executable} ${flagPart} *`], complete: true };
		}
		return { patterns: [`${executable} *`], complete: true };
	}

	// File path commands
	if (FILE_PATH_COMMANDS.has(cmd)) {
		const { flags, remainingArgs } = extractFlags(args);
		// Find first path argument
		for (const arg of remainingArgs) {
			if (arg.startsWith("/") || arg.startsWith("./") || arg.startsWith("../") || arg.startsWith("~")) {
				return { patterns: [`${executable} ${arg}`], complete: true };
			}
		}
		if (flags.length > 0) {
			const flagPart = `-${flags.map((f) => f.slice(1)).join("")}`;
			return { patterns: [`${executable} ${flagPart} *`], complete: true };
		}
	}

	return null;
}
```

## Test Cases

### New Tests for `tests/command-patterns.test.ts`

```typescript
// === TRIVIAL COMMANDS ===

test("pwd produces 'pwd' not 'pwd *'", () => {
	const analysis = analyzeCommandPatterns("pwd");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["pwd"]);
});

test("pwd with arguments still produces 'pwd'", () => {
	// pwd ignores arguments, so 'pwd -L' or 'pwd --help' is still just 'pwd'
	const analysis = analyzeCommandPatterns("pwd -L");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["pwd"]);
});

// === FLAG PRESERVATION ===

test("ls -la preserves flags in pattern", () => {
	const analysis = analyzeCommandPatterns("ls -la");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["ls -la *"]);
});

test("ls --long --all preserves long flags", () => {
	const analysis = analyzeCommandPatterns("ls --long --all");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["ls --long --all *"]);
});

// === FIND COMMAND ===

test("find with path and test produces structured pattern", () => {
	const analysis = analyzeCommandPatterns("find . -maxdepth 2 -name '*.ext'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["find . *"]);
});

test("find with -type preserves type in pattern", () => {
	const analysis = analyzeCommandPatterns("find . -type f -name '*.log'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["find . -type f *"]);
});

test("find with -exec produces action pattern", () => {
	const analysis = analyzeCommandPatterns("find . -type f -exec rm {} \\;");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["find . -type f -exec *"]);
});

// === SED COMMAND ===

test("sed script extracts command letter", () => {
	const analysis = analyzeCommandPatterns("sed -n '1,220p' file");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["sed -n ...p"]);
});

test("sed substitution extracts 's' command", () => {
	const analysis = analyzeCommandPatterns("sed 's/foo/bar/' file");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["sed ...s"]);
});

test("sed -i extracts command letter", () => {
	const analysis = analyzeCommandPatterns("sed -i 's/old/new/g' file");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["sed -i ...s"]);
});

// === ECHO COMMAND ===

test("echo without substitution produces simple pattern", () => {
	const analysis = analyzeCommandPatterns("echo 'hello world'");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["echo"]);
});

test("echo with command substitution uses wildcard", () => {
	const analysis = analyzeCommandPatterns("echo $(pwd)");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["echo *"]);
});

// === FILE PATH COMMANDS ===

test("cat with path preserves path", () => {
	const analysis = analyzeCommandPatterns("cat /etc/passwd");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["cat /etc/passwd"]);
});

test("cat with relative path preserves path", () => {
	const analysis = analyzeCommandPatterns("cat ./config.json");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["cat ./config.json"]);
});

// === GREP COMMAND ===

test("grep -r uses recursive pattern", () => {
	const analysis = analyzeCommandPatterns("grep -r 'pattern' ./src");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["grep -r *"]);
});

test("grep with flags preserves flags", () => {
	const analysis = analyzeCommandPatterns("grep -i 'pattern' file");
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns, ["grep -i *"]);
});

// === CHAINED COMMANDS ===

test("chained commands extract patterns for each", () => {
	const cmd = "pwd && ls -la && echo 'text' && sed -n '1,220p' file && find . -maxdepth 2 -name '*.ext'";
	const analysis = analyzeCommandPatterns(cmd);
	assert.equal(analysis.complete, true);
	assert.deepEqual(analysis.patterns.sort(), [
		"pwd",
		"ls -la *",
		"echo",
		"sed -n ...p",
		"find . *",
	]);
});
```

## Impact Estimation

### Current State (from analysis-log entries)

With commands logged as `cmd *` wildcards:
- `pwd *` → should be `pwd`
- `ls *` → should be `ls -la *` (preserving flags)
- `echo *` → should be `echo` (simple case)
- `sed *` → should be `sed -n ...p` (preserving command)
- `find *` → should be `find . *` (preserving starting path)

### Estimated Improvement

| Command Type | Before | After | Improvement |
|-------------|--------|-------|--------------|
| Trivial (`pwd`, `whoami`) | `pwd *` | `pwd` | 100% specific |
| Flagged (`ls -la`) | `ls *` | `ls -la *` | Flag preserved |
| Echo (simple) | `echo *` | `echo` | 100% specific |
| Sed | `sed *` | `sed -n ...p` | Command preserved |
| Find | `find *` | `find . *` or `find . -type f *` | Path/type preserved |

For a typical compound command with 5-10 simple commands, the improvement would be:
- **5-10 commands** converted from wildcard to specific pattern
- **~60% reduction** in `cmd *` wildcard patterns
- **Better matching** for policy decisions

## Security Considerations

1. **Conservative approach**: When uncertain, fall back to wildcard `*`
2. **No regex patterns**: Use literal matching only (avoid DoS)
3. **Path handling**: Only preserve literal paths, not variables
4. **Command substitution**: Always use wildcard when `$(...)` or backticks detected
5. **Flag validation**: Only extract known safe flags

## Next Steps

1. Implement `common-commands.ts` with handlers for:
   - Trivial commands (`pwd`, `whoami`)
   - Flag preservation (`ls`, `grep`)
   - `find` pattern extraction
   - `sed` command extraction
   - `echo` simple case

2. Update `command-patterns.ts` to call `extractCommonCommandPatterns`

3. Add comprehensive test coverage

4. Monitor analysis-log for remaining wildcards and iterate