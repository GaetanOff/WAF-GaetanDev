# AGENTS.md — Bootstrap IA: Spec Driven Development

> Entrypoint for OpenCode, GitHub Copilot, and all agent-compatible tools.
> Specs are the single source of truth.
> Detailed rules are in `.cursor/rules/core-*.mdc`, `global-*.mdc`, `specific-*.mdc`.

---

## Quick Start — Choose Your Mode

```
New project (no existing code)?
  → Use Greenfield mode: templates/workflows/greenfield.md

Existing project (adding feature or fixing bug)?
  → Use Legacy mode: templates/workflows/legacy.md

Adding a feature to a spec-covered project?
  → Use Feature Addition: templates/workflows/feature-addition.md

Fixing a bug?
  → Use Bug Fix workflow: templates/workflows/bug-fix.md
```

---

## SDD Phase Reference

| Phase | What Happens | Gate to Pass |
|---|---|---|
| 0 — Discovery | 5 questions, actors, constraints, mission.md | All unknowns resolved |
| 1 — Specification | OpenAPI, JSON Schema, Gherkin — status: draft → approved | Spec review approved |
| 2 — Architecture | ADRs, C4 diagrams, data model | ADRs accepted |
| 3 — Planning | Epics → slices → tasks with spec references | Slices defined |
| 4 — Scaffolding | Project structure, tooling, stubs from specs | spec:lint passes |
| 5 — Implementation | Types → migration → failing test → code | Conformance tests pass |
| 6 — Gates | spec:lint, typecheck, conformance, behavior, security, perf, PR checklist | All 7 gates pass |
| 7 — Iteration | Spec change → version bump → code → gate → changelog → release | Release ready |

---

## Critical Invariants — Non-Negotiable

1. **No code before `approved` spec** — always write spec first, get it approved, then implement
2. **No endpoint without OpenAPI contract** — every route has an operationId in the spec
3. **No entity without JSON Schema** — every data shape has a schema with `additionalProperties: false`
4. **No critical behavior without Gherkin** — happy path + 2 error paths minimum
5. **No breaking change without MAJOR bump** — removing fields, renaming, changing types = MAJOR
6. **No breaking change without ADR** — every breaking change has a decision record
7. **No PR without gate check** — all 7 gates in the PR checklist signed off
8. **No vague request → code** — trigger discovery protocol, ask the 5 questions first
9. **Spec wins when code and spec disagree** — fix the code or explicitly update the spec through review
10. **No silent spec changes** — every spec modification is explicit and versioned

---

## Anti-Vibe Coding Protocol

When a request is vague, incomplete, or missing success criteria:

```
Stop. Ask the 5 discovery questions:

1. WHO — What actor triggers this? What system receives the result?
2. WHAT — What is the precise input → transformation → output?
3. WHEN — What conditions trigger this? What are the edge cases?
4. WHY WRONG — What does failure look like? What errors must be handled?
5. DONE — How do we verify it works? What is the acceptance criterion?

Do not write any spec or code until all 5 are answered.
```

---

## Spec Lifecycle

```
draft → reviewed → approved → implemented → validated → deprecated
```

- **`draft`**: No implementation. Spec is being written.
- **`approved`**: Implementation may start. Contract is binding.
- **`implemented`**: Code written. Awaiting conformance validation.
- **`validated`**: All gate checks pass. Release candidate.
- **`deprecated`**: Sunset in progress. Migration guide must exist.

---

## Quality Gates Summary

| Gate | Tool | Blocks |
|---|---|---|
| G1 — Spec lint | `spectral lint` | Merge |
| G2 — Type check | `tsc --noEmit` | Merge |
| G3 — API conformance | `dredd` / `prism` | Merge |
| G4 — Behavior tests | `cucumber-js` | Merge |
| G5 — Security | `npm audit` + SAST | Merge |
| G6 — Performance | `k6` vs SLO thresholds | Release |
| G7 — PR checklist | Human review | Merge |

---

## Spec Templates

Ready-to-use templates in `templates/specs/`:

| Template | Use For |
|---|---|
| `mission.md` | Project problem statement and goals |
| `product-brief.md` | Business context and success metrics |
| `requirements.md` | Functional and non-functional requirements |
| `architecture.md` | C4 diagrams, data model, module structure |
| `api.openapi.yaml` | REST API contracts (OpenAPI 3.1) |
| `schema.json` | JSON Schema data contracts |
| `gherkin.feature` | Behavior specifications |
| `decision-record.md` | Architecture Decision Records |
| `plan.md` | Implementation plan with slices and tasks |
| `tasks.md` | Sprint task list with spec references |
| `validation.md` | Gate check and release validation report |
| `changelog.md` | Keep a Changelog format |

---

## Prompt Library

### Discovery
```
"I want to [feature]. Before any spec or code, ask the 5 SDD discovery questions."
```

### Write Spec
```
"Write [spec type] for [feature] at specs/[path].
Use the template from templates/specs/[template]. Status: draft.
Do not write any implementation code."
```

### Implement a Slice
```
"Implement [feature] against:
@specs/api/[domain].openapi.yaml (operation: [operationId])
@specs/schemas/[entity].schema.json
@specs/features/[feature].feature
Follow SDD order: types → migration → failing test → data → logic → controller."
```

### Gate Check
```
"Run the full gate check: spec:lint, typecheck, test:conformance, test:behavior, security:audit.
Report each gate. Apply the spec-fix workflow for any failure."
```

### Spec Gap Found
```
"STOP. Spec gap found: [description].
Document it, update the spec (status: draft), get it reviewed, then resume."
```

### Bug Fix
```
"Bug: [description]. Apply the SDD debugging decision tree.
Find the spec that defines expected behavior. If missing, write it first."
```

### ADR
```
"We need to decide between [A] and [B] for [requirement].
Draft an ADR at specs/decisions/ADR-[NNN]-[title].md.
Analyze pros/cons against our existing specs. Do not make the decision for me."
```

---

## Core SDD Workflow Rules

### Master Workflow (Spec Driven Development)

Follow this spec-driven approach for every project — never skip phases:

1. **Discovery**: understand requirements, users, constraints, acceptance criteria.
2. **Specification**: write formal specs (OpenAPI, JSON Schema, Gherkin) BEFORE any code.
3. **Contract Design**: design architecture driven by the approved specs.
4. **Scaffolding**: generate project structure with `specs/` directory and conformance tooling.
5. **Spec-First Implementation**: generate conformance tests from specs, then implement to pass them.
6. **Conformance Gates**: validate all contracts hold, all scenarios pass.
7. **Iteration**: evolve specs first when requirements change, then propagate to code.

Never start coding before specs are written and approved. Specs are the single source of truth.

### Specification Authoring

- Write **data contracts** (JSON Schema) for every entity — required fields, types, formats, enums.
- Write **API contracts** (OpenAPI 3.1) for every endpoint — request/response schemas, status codes, error codes.
- Write **GraphQL/gRPC/WebSocket** contracts if applicable to the architecture.
- Write **behavior specs** (Given-When-Then / Gherkin) for every feature — happy path + error paths.
- Write **error contracts** — standard error envelope, error code catalog.
- Write **integration contracts** (Pact) for every external dependency.
- Specs must be machine-readable, human-readable, versioned, and reviewed before implementation.
- Store specs in `specs/` directory: `specs/api/`, `specs/schemas/`, `specs/features/`, `specs/contracts/`, `specs/decisions/`.

### Spec-Driven Observability

- **Structured Logging Contract**: Define standard JSON log shape with correlation (`requestId`) and trace IDs. Never log PII or secrets.
- **Metrics Contract**: RED method (Request rate, Errors, Duration) for APIs. USE method (Utilization, Saturation, Errors) for resources.
- **Distributed Tracing**: Define span naming conventions based on specs. Pass W3C Trace Context between services.
- **SLOs as Code**: Define Service Level Objectives formally in `specs/slos/*.yaml`. Create runbooks for mapped alerts.

### Migration & Versioning Strategy

- **Schema Lifecycle**: Every data contract change produces a versioned, atomic, reversible migration (up/down).
- **API Versioning**: Default to URL path versioning (`/api/v1/`).
- **Data Evolution**: Prefer additive non-breaking changes. Deprecate fields with explicit sunset headers before removal.
- **Compatibility Verification**: Run OpenAPI diff tools in CI to catch unintended breaking changes. Require major version bumps for breaking changes.

### Spec-Driven Planning

- Decompose into epics → features → specs → tasks.
- Define MVP scope as a minimal set of specs that delivers value.
- Write acceptance criteria as executable specifications (Given-When-Then referencing contracts).
- Task breakdown: spec authoring → spec review → conformance tests → data layer → business logic → API → UI → validation.
- Start with foundational contracts (auth, core entities, shared schemas).

### Contract-First Architecture

- Document every decision: Context → Options → Trade-offs → Decision → Consequences → Spec References.
- Architecture is derived from specs: OpenAPI → routes/controllers, JSON Schema → DB models, Gherkin → use cases.
- Choose pattern based on contract shapes: monolith (<10 endpoints), modular monolith (bounded contexts), microservices (separate API specs).
- Data model derived from data contracts. API design derived from API contracts. Error handling from error contracts.
- Cross-cutting concerns defined as shared spec components: error envelope, pagination, auth headers.

### Spec-Driven Scaffolding

- Create `specs/` directory at project root with: `api/`, `schemas/`, `features/`, `contracts/`, `decisions/`.
- Generate initial spec skeleton: OpenAPI, shared error schema, pagination schema, first ADR.
- Set up spec linting (`spectral`), conformance testing (`dredd`/`prism`), code generation (`openapi-generator`).
- Package.json scripts: `spec:lint`, `spec:test`, `spec:generate`.

### Spec-First Implementation

- Build vertical slices: spec → conformance tests → implementation → validation.
- Generate types/interfaces from spec schemas. Generate conformance tests from API contracts.
- Implementation order: shared contracts → conformance harness → auth → core entities → business logic → API → UI.
- Spec Gap Protocol: stop → document gap → update spec → review → write test → resume implementation.
- Every commit leaves the project in a spec-conforming state.

### Conformance Gates

Per feature:
- API responses match OpenAPI spec exactly (schema, status codes, headers).
- Data shapes match JSON Schema contracts.
- All Given-When-Then scenarios pass.
- Error responses match error envelope contract.
- No linter errors. No hardcoded values. No dead code.
- Conformance + unit + integration tests pass. Coverage ≥80% on business logic.
- Security: auth matches spec security schemes, input validated against request schemas.
- Performance: response times meet SLOs from specs.
- Accessibility: semantic HTML, keyboard nav, WCAG AA contrast.

### Spec-Driven Iteration

- When requirements change, update the spec first, then propagate to code.
- Spec changes require review — they affect the contract with consumers.
- Backward-compatible changes: add optional fields, new endpoints, new error codes.
- Breaking changes: major version bump + migration guide.
- Run conformance tests before and after spec changes. Green → evolve → green.
- Track technical debt as spec conformance gaps and spec completeness gaps.

### Agent Orchestration (SDD)

- Reference spec files with @ mentions. Break large tasks into one spec per chat.
- Spec-first prompting: "Write the OpenAPI spec for X" before "Implement X".
- Contract-then-code: spec → conformance tests → implementation → validation.
- Multi-step SDD: data contracts → API contracts → behavior specs → conformance tests → implement → validate.
- Review protocol: check spec completeness, contract consistency, conformance test coverage.

### DevOps

- CI pipeline: install → spec lint → spec validate → type check → conformance tests → unit tests → build → integration tests.
- Use environment variables for all config. Never use production data in dev.
- Containerize services. Multi-stage builds, pin versions, non-root user.
- Monitor with three pillars: logs (structured), metrics (RED/USE), traces (OpenTelemetry).
- Automate backups. Document disaster recovery plan.

### Technology Selection

- Evaluate: fitness, maturity, ecosystem, community, team expertise, scalability, cost.
- SaaS web app: Next.js + React + TypeScript + Tailwind + PostgreSQL + Prisma.
- API backend: Fastify/Hono + TypeScript + PostgreSQL + Zod + Vitest.
- Mobile: React Native + Expo or Flutter.
- CLI: Go (Cobra) or Rust (Clap).
- Always pin dependency versions. Use lockfiles. Audit regularly.

### UX Design

- Clarity over cleverness. Consistency. Feedback on every action. Forgiveness.
- Every interactive element: default, hover, focus, active, disabled, loading states.
- Forms: label every input, inline validation, appropriate input types.
- Design empty states and error states. Provide a path forward from every error.
- Mobile-first responsive. Touch targets ≥44px. WCAG AA contrast.

---

## Global Rules

### Clean Code Fundamentals

- Use descriptive, intention-revealing names. Booleans: `is`, `has`, `should`, `can` prefix.
- Functions: verb phrases, under 20 lines, max 3 parameters, single level of abstraction.
- Prefer early returns / guard clauses over deep nesting.
- No magic numbers or strings — extract to named constants.
- Delete dead code. Don't comment it out.
- Write the simplest code that works. Avoid premature abstraction (Rule of Three).
- Prefer composition over inheritance.

### Error Handling

- Fail fast: validate at boundaries, reject bad data early.
- Never swallow errors silently. Use specific error types with contextual messages.
- Catch at the appropriate level. Clean up resources in `finally` / `defer` / `with`.
- Log at correct severity (debug, info, warn, error). Include correlation IDs.
- Never log sensitive data (passwords, tokens, PII).

### Security

- Never trust user input. Validate and sanitize at system boundaries.
- Use parameterized queries — never concatenate user input into SQL.
- Never hardcode secrets in source code. Use env vars or a secrets manager.
- Hash passwords with bcrypt/scrypt/argon2. Validate authorization server-side on every request.
- Keep dependencies up to date. Run security audits regularly.

### Testing (Spec-Driven)

- Conformance tests (40%): spec-generated, validate contracts hold.
- Unit tests (30%): fast, isolated, test business logic beyond specs.
- Integration tests (20%): test component interactions and data flow.
- E2E tests (10%): test critical user flows from behavior specs.
- Follow Arrange-Act-Assert. One contract per test. Descriptive test names.
- Tests must be deterministic. No shared mutable state between tests.
- Mock external dependencies at the contract boundary (Pact mock server).

### Git Conventions

- Conventional Commits: `<type>(<scope>): <description>`. Types: feat, fix, refactor, docs, test, chore, perf, ci, spec, adr.
- Imperative mood, lowercase, no period, max 72 chars subject line.
- One logical change per commit. Keep PRs small (<400 lines diff).
- Branch naming: `feat/<ticket>-description`, `fix/<ticket>-description`, `spec/<ticket>-description`.
- Never commit secrets, `.env`, or build artifacts.

### Documentation (Spec-Driven)

- Specs ARE documentation. API docs auto-generated from OpenAPI. Type docs from JSON Schema.
- Code comments explain **why**, not **what**. Reference specs for contract context.
- Every project needs: README.md, .env.example, spec overview.
- ADRs stored in `specs/decisions/`, referencing the specs that drove them.

### Performance

- Measure first, optimize second. Algorithmic improvements beat micro-optimizations.
- Watch for N+1 queries, unnecessary re-renders, main thread blocking, large payloads.
- Cache at the right layer with proper invalidation.
- Use async I/O, parallel execution, connection pooling.
- Paginate list endpoints. Lazy-load non-critical resources.

### SOLID Principles

- **SRP**: One reason to change per module/class/function.
- **OCP**: Open for extension, closed for modification.
- **LSP**: Subtypes must be substitutable for their base types.
- **ISP**: Don't force clients to depend on methods they don't use.
- **DIP**: Depend on abstractions, not concrete implementations. Inject dependencies.
- **DRY**: Extract duplicated logic, but wait for 3 occurrences before abstracting.
- **KISS/YAGNI**: Simplest solution wins. Don't build what you don't need yet.

### Project Structure

- Organize by feature/domain, not by file type. Colocate related files.
- `specs/` directory at project root — single source of truth for all contracts.
- Flat structure — max 3-4 levels deep. Each directory has one clear purpose.
- Define module boundaries. Expose public APIs, hide internals. No circular dependencies.

### Code Review

- Self-review every diff before submitting. No debug code or console logs.
- Review for: spec conformance, correctness, security, maintainability, performance, test coverage.
- Give specific feedback. Distinguish blockers from suggestions. Ask questions, don't demand.

---

## Technology-Specific Rules

### TypeScript

- Enable `strict: true`. Avoid `any` — use `unknown` + type guards.
- Prefer `interface` for extendable shapes, `type` for unions/intersections.
- Use discriminated unions for state modeling. Use `readonly` for immutable data.
- Use optional chaining (`?.`) and nullish coalescing (`??`). Prefer explicit null checks over `!`.
- Use `import type` for type-only imports.

### React

- Functional components only. One per file. Keep JSX under ~50 lines.
- Destructure props. Follow Rules of Hooks. One effect per concern.
- Start with local state, lift up only when needed. Don't store derived state.
- Memoize with `useMemo`/`useCallback` only when measurably needed.
- Don't use array index as `key`. Don't mutate state directly.

### Next.js (App Router)

- Default to Server Components. Push `"use client"` boundary as low as possible.
- Fetch data in Server Components with `async/await`. Use `loading.tsx` and `error.tsx`.
- Use Server Actions for mutations. Validate with Zod.
- Use `<Image>` and `<Link>` components. Implement `generateMetadata` for SEO.

### Python

- Follow PEP 8 (Black/Ruff formatter). Type hints on all function signatures.
- Use dataclasses/Pydantic for structured data. Context managers for resources.
- Catch specific exceptions. Use `logging`, not `print()`.
- Use `pytest` with fixtures and parametrize. `pyproject.toml` for config.

### Node.js

- Always `async/await`. Never forget `await`. Use `Promise.all()` for parallel ops.
- Centralized error middleware. Custom error classes. Consistent error response shapes.
- Validate requests with Zod/Joi. Use structured logging (pino/winston).
- Handle graceful shutdown. Use connection pooling.

### CSS & Tailwind

- Use utility classes directly. Extract to components, not `@apply`.
- Mobile-first responsive: default → `sm:` → `md:` → `lg:`.
- Use `cn()` / `clsx` for conditional classes. Group classes logically.
- Ensure WCAG AA contrast. Support `prefers-reduced-motion`.

### SQL & Database

- Parameterized queries always. Never `SELECT *` in application code.
- Add `NOT NULL` by default. Use `created_at`/`updated_at` timestamps.
- One atomic change per migration. Migrations must be reversible.
- Watch for N+1 queries. Use transactions for atomic operations.

### Docker

- Multi-stage builds. Minimal base images. Pin versions.
- Order layers by change frequency. Don't run as root.
- Use `.dockerignore`. Set `HEALTHCHECK`. Scan for vulnerabilities.

### Rust

- Prefer borrowing over cloning. Use `Result<T, E>` for recoverable errors.
- Use `thiserror` (libraries) / `anyhow` (apps). Avoid `unsafe` unless justified.
- Use iterators/combinators. Derive `Debug`, `Clone`, `PartialEq`.
- Run `clippy` and `rustfmt` in CI.

### Go

- Follow `gofmt`. Always check returned errors. Wrap with `%w` for context.
- Accept interfaces, return structs. Keep interfaces small (1-2 methods).
- Use `context.Context` for cancellation. Manage goroutine lifecycles.
- Table-driven tests. Minimize external dependencies.

### Vue.js 3

- Use `<script setup>` + Composition API. `ref()` for primitives, `reactive()` for objects.
- Extract logic into composables (`useXxx`). Use `computed()` for derived state.
- Use Pinia for state management. Lazy-load routes.
- Use `defineProps<T>()` and `defineEmits<T>()` for type safety.

### C#

- Follow .NET naming: `PascalCase` public, `_camelCase` private fields, `I` prefix for interfaces.
- Use records for immutable DTOs. Use `sealed` on classes not designed for inheritance.
- Always `async/await` — never `.Result` or `.Wait()`. Pass `CancellationToken` through call chains.
- Use `ValueTask<T>` for hot paths. Use `ConfigureAwait(false)` in library code.
- Enable nullable reference types (`<Nullable>enable</Nullable>`). Use pattern matching and switch expressions.
- Constructor injection for DI. `IOptions<T>` for config. Validate options at startup.
- LINQ: `Any()` over `Count() > 0`. Avoid multiple enumeration of `IEnumerable<T>`.

### Java

- Use modern Java (17+): records, sealed classes, pattern matching, switch expressions, text blocks.
- Use `Optional<T>` as return type for absent values — never as field or parameter.
- `Objects.requireNonNull()` for fail-fast. Try-with-resources for all `AutoCloseable`.
- Use `List.of()`, `Map.of()`, `Set.of()` for immutable collections. Streams for transformations.
- Constructor injection (Spring). `@Valid` for input validation. `@RestControllerAdvice` for errors.
- JUnit 5 + Mockito + AssertJ. `@SpringBootTest` only for integration tests.

### Swift & SwiftUI

- Prefer `struct` (value types) over `class` (reference types) by default.
- Use optional binding (`if let`, `guard let`) safely; avoid force-unwrapping (`!`).
- Embrace modern Swift concurrency (`async`/`await`, `Task`). Avoid GCD where possible.
- In SwiftUI, separate logic from presentation. Use `@StateObject` and `@ObservedObject` correctly.
- Derive `Codable` models directly from JSON Schema data contracts.

### Kotlin & Android

- Prefer `val` (read-only) over `var` (mutable). Use single-expression functions when appropriate.
- Embrace null safety; avoid the not-null assertion operator (`!!`).
- Use `sealed class` or `sealed interface` for exhaustive UI state modeling.
- Use Coroutines (`suspend`) for async operations, and `StateFlow`/`SharedFlow` for streams.
- Use Jetpack Compose for declarative UI. Hoist state up and follow Unidirectional Data Flow (UDF).

### Dart & Flutter

- Follow official Dart style. `dart format` enforced. `PascalCase` types, `camelCase` variables, `_prefix` private.
- Embrace sound null safety. Avoid `!` assertion — handle null explicitly. Prefer `final` by default.
- Use sealed classes (Dart 3) + pattern matching for exhaustive state modeling.
- Use `const` constructors for widgets. Extract widgets into classes, don't nest deeply.
- Riverpod/Bloc/Provider for state (pick one). Separate logic from UI.
- `async/await` for Futures. Always handle errors. Use `mocktail` for testing.

### C

- Every `malloc`/`calloc` must have a matching `free`. Check for `NULL` on allocation.
- Set pointers to `NULL` after freeing. Use `sizeof(*ptr)` for allocation size.
- Use bounded functions: `snprintf` over `sprintf`, `fgets` over `gets`.
- Track buffer sizes alongside pointers. Guard against integer overflow.
- Use `goto cleanup` pattern for multi-resource functions.
- Return error codes: `0` success, negative for errors. `const` everything possible.
- Use `<stdint.h>` fixed-size types. Compile with `-Wall -Wextra -Werror`.
- Run sanitizers (`-fsanitize=address,undefined`) and static analysis (cppcheck, clang-tidy).

### C++

- Never raw `new`/`delete`. Use `std::make_unique` (default), `std::make_shared` (shared ownership only).
- RAII for every resource. Pass `T&`/`const T&` to functions, not smart pointers (unless transferring ownership).
- Use `std::optional`, `std::variant`, `std::string_view`, structured bindings, `constexpr`.
- Use `std::span<T>` for non-owning contiguous views. `std::expected<T,E>` (C++23) for error handling.
- Mark everything `const`: variables, references, member functions. `noexcept` on move ops and destructors.
- Prefer STL containers and `<algorithm>` / `<ranges>`. Reserve vector capacity when known.
- `std::mutex` + `std::scoped_lock` for shared data. `std::atomic` for simple counters.
- Compile with `-Wall -Wextra -Wpedantic -Werror`. Use clang-tidy with Core Guidelines.

### REST API Design

- Nouns for resources, plural: `/users`, `/orders`. Shallow nesting (max 2-3 levels).
- Correct HTTP methods and status codes. Consistent response envelope.
- Version APIs (`/api/v1/`). Paginate all list endpoints. Rate limit everything.
- Document with OpenAPI/Swagger — the spec IS the API documentation.
