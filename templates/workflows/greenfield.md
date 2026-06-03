# Greenfield Project Workflow

Use this workflow when starting a new project from scratch.

---

## Phase 0 — Discovery

**Goal**: Understand the problem before any technical decision is made.

```bash
# Artifacts to create
specs/
├── mission.md           # Problem, actors, goals, non-goals
└── decisions/
    └── ADR-000-project-context.md
```

**Agent prompt to start discovery**:
```
I want to build [project description].
Before any spec or code, run the SDD discovery protocol.
Ask the 5 minimum questions: WHO, WHAT, WHEN, WHY WRONG, DONE.
Do not proceed until I answer them.
```

**Gate to pass**: All discovery questions answered. `mission.md` written and approved.

---

## Phase 1 — Specification

**Goal**: Write all contracts before any code.

```bash
# Artifacts to create
specs/
├── requirements.md           # FR + NFR
├── api/
│   └── [domain].openapi.yaml # API contracts (status: draft)
├── schemas/
│   └── [entity].schema.json  # Data contracts (status: draft)
├── features/
│   └── [feature].feature     # Behavior specs (status: draft)
└── slos/
    └── api.slo.yaml           # Service Level Objectives
```

**Agent prompt sequence**:
```
Step 1 — Data contracts:
"Write JSON Schema for [entity] at specs/schemas/[entity].schema.json.
Use the template from templates/specs/schema.json. Status: draft.
Do not write any code."

Step 2 — API contracts:
"Write the OpenAPI 3.1 spec for [domain] at specs/api/[domain].openapi.yaml.
Reference the schemas from Step 1. Use templates/specs/api.openapi.yaml.
Status: draft. Do not write any code."

Step 3 — Behavior specs:
"Write Gherkin scenarios for [feature] at specs/features/[feature].feature.
Cover: happy path, authentication error, validation error, not found.
Status: draft. Do not write any code."
```

**Gate to pass**: All specs at `status: approved` after human review.

---

## Phase 2 — Architecture

**Goal**: Design the system from approved specs.

```bash
specs/decisions/
├── ADR-001-[title].md   # Tech stack decision
├── ADR-002-[title].md   # Auth decision
└── ADR-003-[title].md   # Data persistence decision
```

**Agent prompt**:
```
"Based on @specs/requirements.md and @specs/api/[domain].openapi.yaml,
propose the architecture for this project.
For each significant decision (tech stack, auth, DB), draft an ADR
at specs/decisions/ADR-[NNN]-[title].md.
Do not write any implementation code."
```

**Gate to pass**: Architecture ADRs reviewed and accepted.

---

## Phase 3 — Planning

**Goal**: Break specs into implementable tasks.

```bash
specs/
├── plan.md    # Epic → slices → tasks
└── tasks.md   # Sprint task list with spec references
```

**Agent prompt**:
```
"Based on @specs/requirements.md and @specs/plan.md template,
create an implementation plan decomposed into vertical slices.
Each slice must include: spec reference, task order (spec → type gen →
migration → conformance test → implementation → gate check).
Use templates/specs/plan.md as the template."
```

---

## Phase 4 — Scaffolding

**Goal**: Generate project structure aligned with approved specs.

```bash
# Project structure
src/
├── modules/[domain]/
│   ├── [entity].schema.ts       # Generated from JSON Schema
│   ├── [entity].repository.ts
│   ├── [entity].service.ts
│   └── [entity].controller.ts
├── shared/errors.ts
└── app.ts

# Tooling setup
package.json scripts:
  spec:lint     → spectral lint specs/api/
  spec:generate → openapi-generator + json-schema-to-typescript
  spec:test     → dredd or prism
  typecheck     → tsc --noEmit
```

**Agent prompt**:
```
"Scaffold the project for [Project Name].
1. Create the directory structure from @specs/decisions/ADR-001-[title].md
2. Configure spectral for spec:lint
3. Configure openapi-generator for spec:generate
4. Configure dredd for spec:test
5. Generate initial TypeScript types from @specs/schemas/*.schema.json
6. Create .env.example with all required environment variables
Do not write any business logic."
```

---

## Phase 5 — Implementation

**Goal**: Build vertical slice by vertical slice.

**For each slice**:
```
1. "Confirm @specs/api/[domain].openapi.yaml is at status: approved."
2. "Generate types from @specs/schemas/[entity].schema.json"
3. "Write failing conformance test for [operationId]"
4. [Verify test fails for the right reason]
5. "Implement the repository layer for [entity]"
6. "Implement the service layer for [feature]"
7. "Implement the controller for [operationId]"
8. [Verify conformance test passes]
9. "Run npm run spec:lint typecheck test:conformance test:behavior"
10. [If all pass: promote spec to status: implemented]
```

---

## Phase 6 — Validation & Release

```bash
# Run full gate check
npm run spec:lint
npm run typecheck
npm run test:conformance
npm run test:behavior
npm run security:audit
npm run test:perf
```

**Agent prompt**:
```
"Run the full gate check for [feature]:
1. spec:lint — report any errors
2. typecheck — report any type errors
3. test:conformance — report pass/fail per endpoint
4. test:behavior — report pass/fail per scenario
5. security:audit — report any findings
For each failure, apply the spec-fix workflow and report which path was taken."
```

**Post-release checklist**:
```bash
# Update CHANGELOG.md
# Promote specs to status: validated
# Update SPEC-INDEX.md
# Create git tag
git tag -a v1.0.0 -m "Initial release"
git push origin v1.0.0
```
