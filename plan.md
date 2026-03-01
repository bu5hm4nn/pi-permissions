# Parser Architecture Refactor Plan

## Goal
Modularize shell parsing and command analysis so security blocking (`ssh/matcher`) and policy extraction (`policy/command-patterns`) share one parser core and cannot drift.

## Why
Current state has duplicated logic across:
- `src/ssh/matcher.ts`
- `src/policy/command-patterns.ts`

This duplication increases:
- behavior drift risk (different wrapper/support handling)
- security inconsistencies (fail-closed in one path, heuristic in another)
- maintenance cost for large command families (docker/curl, future kubectl/git/etc.)

---

## Target Structure

```txt
src/
  shell/
    parser/
      parse.ts                # bash-parser adapter + normalized parse result
      ast-walk.ts             # shared AST traversal utilities
      tokens.ts               # escaping/literal/token normalization helpers
      wrappers.ts             # wrapper grammar + stepping/resolution
      resolve-head.ts         # executable head resolution + certainty
      types.ts                # shared certainty/result types
    analyzers/
      direct-ssh.ts           # direct SSH-family detection
      command-patterns.ts     # generic pattern extraction
      docker-patterns.ts      # docker run/exec nested command extraction
      curl-patterns.ts        # curl method-aware pattern extraction
    fallback/
      heredoc.ts              # heredoc stripping for legacy fallback
      legacy-matcher.ts       # legacy segment/token matcher (if retained)
  ssh/
    matcher.ts                # thin adapter over shell/analyzers/direct-ssh
  policy/
    command-patterns.ts       # thin adapter over shell/analyzers/command-patterns
```

---

## Core Invariants

1. **Single source of truth** for:
   - token/literal normalization
   - wrapper parsing semantics
   - executable head resolution

2. **Explicit certainty model** everywhere:
   - `resolved`
   - `uncertain`

3. **Fail-closed rules**:
   - matcher: uncertain => block
   - reusable policy extraction: uncertain/incomplete => no reusable approvals

4. **Stable external APIs**:
   - keep `isDirectSshFamilyCommand(command)`
   - keep `analyzeCommandPatterns(command)`

---

## Phased Migration

### Phase 0 — Freeze behavior (safety net)
- Add/keep characterization tests for current behavior.
- Ensure current regression tests pass before refactor.

### Phase 1 — Shared primitives extraction (no behavior change)
- Introduce:
  - `src/shell/parser/tokens.ts`
  - `src/shell/parser/wrappers.ts`
- Move duplicated helpers from matcher/patterns files.
- Rewire both modules to shared helpers.

### Phase 2 — Shared parser and traversal
- Add:
  - `parse.ts`, `ast-walk.ts`, `resolve-head.ts`, `types.ts`
- Keep old files as adapters that consume shared parser core.

### Phase 3 — Analyzer split
- Move logic into:
  - `analyzers/direct-ssh.ts`
  - `analyzers/command-patterns.ts`
  - `analyzers/docker-patterns.ts`
  - `analyzers/curl-patterns.ts`
- `src/ssh/matcher.ts` and `src/policy/command-patterns.ts` become thin wrappers.

### Phase 4 — Fallback isolation + policy decision
- Isolate legacy fallback in `shell/fallback/*`.
- Decide strict mode behavior:
  - default strict: parse failure => block
  - optional compatibility mode: fallback + conservative block on disagreement

### Phase 5 — Cleanup + docs
- Remove old duplicate internals.
- Add short architecture docs in `src/shell/README.md`.

---

## Testing Strategy

### Unit tests by module
- `tokens`: escape/quote/literal cases
- `wrappers`: option stepping for sudo/env/command/time/nice/exec/etc.
- `resolve-head`: wrapper chains + env assignments
- `curl-patterns`: method variants (`-X`, `--request`, `-d`, `-F`, `--json`, `-G`, `-I`, `-T`, `--next`)
- `docker-patterns`: `run/exec`, `--` separators, nested shell payloads

### Cross-module consistency tests
- Same command through matcher + pattern analyzer should use same resolution semantics.
- Ensure no drift between analyzers on shared parse/resolution outcomes.

### Security invariants tests
- uncertain parse/node => matcher blocks
- incomplete extraction => reusable approvals disabled
- no-UI unknown or uncertain => deny

### Regression corpus
- Keep fixture corpus of tricky commands:
  - heredocs
  - arrays/loops
  - process substitution
  - malformed shell
  - nested docker shell payloads

---

## Immediate First PR (low risk)

1. Create `src/shell/parser/tokens.ts` and `src/shell/parser/wrappers.ts`.
2. Import these from both `src/ssh/matcher.ts` and `src/policy/command-patterns.ts`.
3. Do not change behavior.
4. Confirm all existing tests remain green.

---

## Risks & Mitigations

- **Risk:** behavior regressions during extraction
  - **Mitigation:** characterization tests + small phases

- **Risk:** accidental fail-open during parser migration
  - **Mitigation:** enforce certainty contract and fail-closed checks in tests

- **Risk:** parser feature growth reintroduces monoliths
  - **Mitigation:** keep command-family analyzers isolated (`curl`, `docker`, etc.)
