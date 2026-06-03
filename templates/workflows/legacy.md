# Legacy Project Workflow

Use this workflow when working on an existing codebase without full spec coverage.
This workflow is non-destructive — it never requires rewriting existing code to match new specs.

---

## Step 0 — Spec Audit

Before touching any code, inventory the current spec coverage.

```bash
# Check what specs exist
ls specs/ 2>/dev/null || echo "No specs/ directory"

# Check for any existing API docs
find . -name "*.yaml" -o -name "*.yml" -o -name "swagger.json" | grep -v node_modules
find . -name "*.feature" | grep -v node_modules
```

**Audit checklist**:
```
[ ] specs/ directory exists?
[ ] OpenAPI spec exists? (any version)
[ ] JSON Schema files exist?
[ ] Gherkin feature files exist?
[ ] Any documentation describing expected API behavior?
[ ] Any existing tests that document expected behavior?
```

**Maturity level assessment**:
- L0: No specs directory, no API docs, no formal contracts
- L1: Some docs, partial coverage
- L2+: Significant coverage already exists — adapt workflow accordingly

---

## Step 1 — Retro-Spec: Document Existing Behavior

Write specs that describe what the system **currently does**, not what it should do.
This is the most important rule in the legacy workflow: **describe reality, not ideals**.

**Agent prompt**:
```
"Write retro-specs for @src/[module]/.
These specs describe CURRENT behavior as-is — do not improve or change anything.
1. Read the existing code to understand what it does
2. Write JSON Schema for each entity at specs/schemas/[entity].schema.json
3. Write OpenAPI entries for each route at specs/api/[domain].openapi.yaml
4. Write 2-3 Gherkin scenarios for the most critical behaviors
Mark all specs with status: implemented (they describe existing behavior).
Do not change any code."
```

**Output**: Retro-specs that serve as a safety net before any changes.

---

## Step 2 — Gap Analysis

Identify the delta between current behavior and desired behavior.

**Agent prompt**:
```
"Compare @specs/requirements.md (desired behavior) with the retro-specs in @specs/.
List:
1. Behaviors that SHOULD CHANGE (delta specs needed)
2. Behaviors that SHOULD STAY (retro-specs are final — do not touch)
3. Missing coverage (spec debt — no spec exists for this behavior)
Format as a table: [Behavior] | [Current] | [Desired] | [Breaking?]
Do not write any code or specs yet."
```

---

## Step 3 — Delta Specs

Write specs for what changes. Do not modify retro-specs.

```bash
# Delta spec naming convention
specs/api/[domain]-v2.openapi.yaml    # New version of existing spec
specs/schemas/[entity]-v2.schema.json  # New version of existing schema
specs/features/[feature]-new.feature  # New scenarios for changed behaviors
```

**Rules for delta specs**:
- Delta specs have `status: draft`
- They describe the target state, not the current state
- They reference the retro-spec they modify or supersede
- Breaking changes require a MAJOR version bump and an ADR

**Agent prompt**:
```
"For the delta changes identified in the gap analysis:
1. Write delta specs (what changes) — these are additive to retro-specs
2. For each breaking change, draft an ADR at specs/decisions/ADR-[NNN].md
3. Mark all delta specs with status: draft
Do not touch retro-specs. Do not write any implementation code."
```

---

## Step 4 — Migration Planning

Plan the migration from current to target state.

```bash
# Create migration plan
specs/
├── plan.md          # Slices that migrate from old behavior to new
└── decisions/
    └── ADR-[NNN]-migration-strategy.md
```

**Key migration questions to answer**:
1. Can we migrate in-place (same version) or must we version the API?
2. Are there external consumers of this API that will break?
3. Is there existing data that must be migrated?
4. What is the rollback plan for each slice?

---

## Step 5 — Incremental Implementation

Implement slice by slice. Each slice must:
1. Keep all retro-spec conformance tests passing
2. Also pass the new delta-spec conformance tests

**Agent prompt per slice**:
```
"Implement slice [N] for [feature].
Constraints:
- All retro-spec tests in @specs/features/[retro].feature must still pass
- The delta-spec tests in @specs/features/[delta].feature must now pass
- Do not break any existing API contracts unless the delta spec explicitly changes them
Run the conformance suite before AND after each change."
```

---

## Step 6 — Regression Validation

After each slice, validate no regression occurred.

```bash
# Run retro-spec conformance (must still pass)
npm run test:conformance -- --spec specs/api/[domain]-retro.openapi.yaml

# Run delta-spec conformance (must now pass)
npm run test:conformance -- --spec specs/api/[domain]-v2.openapi.yaml
```

---

## Step 7 — Spec Debt Backlog

After the immediate work is done, register all identified spec debt:

```markdown
# specs/spec-debt.md

| ID | Description | Spec | Priority | Status |
|---|---|---|---|---|
| SD-001 | No Gherkin scenarios for error paths in checkout | feat-checkout | High | Open |
| SD-002 | Order schema missing `cancelledAt` field | schema-order | Medium | Open |
```

Track spec debt as part of normal sprint planning. High-priority debt is a release gate.
