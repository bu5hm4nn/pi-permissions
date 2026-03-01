# Refactor TODO

- [x] Phase 1: Extract shared parser token/wrapper helpers.
- [x] Rewire `src/ssh/matcher.ts` to shared token/wrapper helpers.
- [x] Rewire `src/policy/command-patterns.ts` to shared token/wrapper helpers.
- [x] Phase 2 (scaffolding): Add `types.ts`, `parse.ts`, `ast-walk.ts`, `resolve-head.ts`.
- [x] Phase 2 (partial): Reuse `resolve-head.ts` from `ssh/matcher` and `policy/command-patterns` with shared tests.
- [x] Phase 2: Integrate parser scaffolding into existing analyzers.
- [x] Phase 3: Split analyzers into dedicated modules and keep adapter APIs stable.
- [x] Phase 4+: Isolate fallback modules and complete remaining cleanup/docs per `plan.md`.
  - [x] Isolate legacy matcher/tokenization + heredoc handling into `src/shell/fallback/*` with direct-ssh analyzer wiring preserved.
  - [x] Make parse-failure strict-vs-compat decision explicit via `DIRECT_SSH_PARSE_FAILURE_MODE` (default `"compat"` to preserve current behavior).
  - [x] Complete Phase 5 cleanup/docs (`src/shell/README.md` and final duplicate-internals audit).
