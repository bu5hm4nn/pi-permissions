# Parser Refactor Release Notes (Phases 1–5)

Date: 2026-02-27

## Summary
Completed the parser architecture refactor to reduce drift between SSH blocking and command-pattern extraction, while preserving public adapter APIs and current approved behavior.

Refactor outcomes:
- Shared parser primitives centralized.
- Analyzer logic split into focused modules.
- Legacy fallback isolated.
- Architecture and invariants documented.
- Full test suite expanded and passing.

---

## Scope Completed

### Phase 1 — Shared primitives extraction
Created shared parser modules and rewired consumers:
- `src/shell/parser/tokens.ts`
- `src/shell/parser/wrappers.ts`
- `src/shell/parser/resolve-head.ts`

Integrated into:
- `src/ssh/matcher.ts`
- `src/policy/command-patterns.ts`

Added shared behavior tests:
- `tests/shell-parser-shared.test.ts`

### Phase 2 — Shared parser + traversal usage
Adopted common parser/traversal utilities:
- `src/shell/parser/parse.ts`
- `src/shell/parser/ast-walk.ts`
- `src/shell/parser/types.ts`

Security regression fixed with TDD:
- matcher now fail-closes when SSH appears in function-definition/invocation path.

### Phase 3 — Analyzer split
Split analysis logic into dedicated modules:
- `src/shell/analyzers/direct-ssh.ts`
- `src/shell/analyzers/command-patterns.ts`
- `src/shell/analyzers/docker-patterns.ts`
- `src/shell/analyzers/curl-patterns.ts`

Adapters kept stable:
- `src/ssh/matcher.ts` (thin adapter)
- `src/policy/command-patterns.ts` (thin adapter)

Added module-level parity tests:
- `tests/analyzers-modules.test.ts`

### Phase 4 — Fallback isolation + explicit mode
Isolated compatibility fallback:
- `src/shell/fallback/heredoc.ts`
- `src/shell/fallback/legacy-matcher.ts`

Made parse-failure behavior explicit in direct SSH analyzer:
- Initial rollout exposed `DIRECT_SSH_PARSE_FAILURE_MODE: "strict" | "compat"`
- Current runtime has been migrated to **strict-only fail-closed** (compat mode removed from runtime path)

Added fallback tests:
- `tests/shell-fallback.test.ts`

### Phase 5 — Cleanup + docs
Added architecture documentation:
- `src/shell/README.md`

Documented:
- parser/analyzer/fallback boundaries
- certainty model
- fail-closed semantics
- current strict fail-closed parse-failure behavior

---

## Behavior Notes

### Preserved behavior
- Public APIs unchanged:
  - `isDirectSshFamilyCommand(command)`
  - `analyzeCommandPatterns(command)`
- Existing project decisions preserved:
  - pattern-based approvals
  - project-local policy storage
  - restricted prompt options for reusable-unsafe flows

### Security-related improvements
- Function-definition/invocation SSH path now explicitly fail-closed in matcher traversal.
- Direct SSH parse-failure decision now centralized and explicit.

---

## Test Status

Final status after Phase 5:
- `npm test` → **37 passed, 0 failed**

New/expanded coverage includes:
- shared parser head resolution/traversal
- analyzer-module adapter parity
- fallback module contracts
- docker nested command extraction variants (`run`/`exec`, `--` handling)
- curl method-aware pattern extraction (`GET/POST/PUT/DELETE` + key flag variants)

---

## Suggested Next Steps

1. Optional hardening tests:
   - mixed-case wrapper chains and executable paths in matcher regressions.
2. Optional: remove or archive legacy fallback module code if no longer needed for regression reference.
3. Add concise user-facing note in README/docs about parser architecture and current parse-failure mode.
