# Shell analysis architecture

This directory is the shared shell-analysis core used by:

- `src/ssh/matcher.ts` (direct SSH-family blocking)
- `src/policy/command-patterns.ts` (reusable allow-pattern extraction)

Both adapters are intentionally thin and delegate to analyzers here to avoid parser drift.

## Boundaries

### `parser/`
Common, command-family-agnostic primitives:

- `parse.ts`: `bash-parser` adapter that returns a certainty-tagged parse result.
- `ast-walk.ts`: tolerant AST walker used by analyzers.
- `tokens.ts`: literal/token normalization and escape helpers.
- `wrappers.ts`: wrapper grammar stepping (`sudo`, `env`, `command`, `time`, etc.).
- `resolve-head.ts`: wrapper-aware executable head resolution.
- `command-node.ts`: extraction of literal command-node head/suffix parts.

`parser/*` does **not** decide policy. It only exposes normalized parse/resolve facts.

### `analyzers/`
Policy-facing analysis logic built on parser primitives:

- `direct-ssh.ts`: detects SSH-family execution with fail-closed behavior.
- `command-patterns.ts`: extracts reusable command patterns.
- `docker-patterns.ts`, `curl-patterns.ts`: command-family-specific extraction helpers.

Analyzers own security/policy decisions, not parser helpers.

### `fallback/`
Legacy parser utilities retained for regression tests and historical reference:

- `legacy-matcher.ts`
- `heredoc.ts`

Direct SSH detection no longer uses compatibility fallback at runtime.

## Certainty and fail-closed semantics

Core certainty model:

- `resolved`: parser produced an AST.
- `uncertain`: parser unavailable/failed, malformed constructs, or dynamic/unknown nodes.

Fail-closed rules:

1. **Direct SSH matcher (`analyzers/direct-ssh.ts`)**
   - On resolved AST: any blocked SSH-family head => block.
   - Any uncertain/dynamic AST state (`onUnknown`, function nodes, unresolved literals) => block.
   - Parse failure mode is strict-only: parser failure/unavailability blocks immediately.

2. **Command pattern analysis (`analyzers/command-patterns.ts`)**
   - Returns `complete: false` when uncertain/incomplete extraction occurs.
   - Incomplete analysis must not be treated as reusable-safe approval input.

This separation ensures a single parser source of truth with analyzer-specific fail-closed policy behavior.
