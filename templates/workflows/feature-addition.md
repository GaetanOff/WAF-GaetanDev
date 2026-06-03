# Feature Addition Workflow

Use this workflow when adding a feature to an existing project with spec coverage.

---

## Pre-Flight Check

Before starting, answer these questions:

```
1. Does a specs/ directory exist?        YES / NO
2. Are existing specs at L2+ maturity?   YES / NO
3. Does this feature touch existing specs? YES / NO
4. Is this feature backward-compatible?  YES / NO
```

If `specs/` does not exist → use the **Legacy Workflow** first to establish baseline specs.

---

## Step 1 — Discovery (always required)

Even for small features, run the minimum discovery protocol.

**Agent prompt**:
```
"I want to add [feature description] to the existing project.
Before any spec, ask the 5 discovery questions for this delta.
Specifically check: does this feature conflict with any existing spec?
Reference @specs/ to understand current contracts."
```

**Minimum artifacts**:
- Updated `specs/requirements.md` with the new FR/NFR items
- Confirmation that no existing spec contradicts the new feature

---

## Step 2 — Delta Spec

Write only what changes. Do not duplicate existing specs.

```bash
# Options (choose based on scope of change):
# A) Add new paths to existing OpenAPI spec
# B) Create a new spec file for a new resource
# C) Create a new version (v2) if changing existing contracts
```

**Agent prompt**:
```
"Write the delta spec for [feature]:
1. Check @specs/api/[domain].openapi.yaml — what already exists?
2. Add new paths/schemas for the new feature (do not duplicate existing)
3. If this changes an existing endpoint, check if it's a breaking change
4. If breaking: write ADR at specs/decisions/ADR-[NNN].md
5. Set status: draft on all new/modified spec sections
Do not write any code."
```

---

## Step 3 — Review

Before implementation starts, the delta spec must be at `status: approved`.

**Review checklist**:
```
[ ] New spec sections do not contradict existing approved specs
[ ] If breaking: MAJOR version bump is proposed
[ ] If breaking: ADR is written and accepted
[ ] New fields/endpoints have types, formats, examples
[ ] Error cases are documented
[ ] No TODO/TBD in the spec
```

---

## Step 4 — Implementation

Implement strictly against the approved delta spec.

**Agent prompt**:
```
"Implement [feature] strictly against the approved delta spec:
@specs/api/[domain].openapi.yaml (sections: [list new operationIds])
@specs/schemas/[entity].schema.json (new fields: [list])

Implementation order:
1. Generate/update TypeScript types
2. Write failing conformance test for new operationIds
3. Implement data layer (migration if needed)
4. Implement service logic
5. Implement controller
6. Verify conformance tests pass
7. Verify existing tests are not broken"
```

---

## Step 5 — Gate Check

```bash
npm run spec:lint       # No new warnings introduced
npm run typecheck       # Types are consistent
npm run test:conformance # New AND existing endpoints pass
npm run test:behavior    # New AND existing scenarios pass
npm run security:audit   # No new vulnerabilities
```

---

## Step 6 — Changelog & Release

```markdown
## [Unreleased]

### Added
- [New feature description] (spec: api-[domain]-[NNN] v[X.Y.Z])
```

If breaking:
```markdown
## [X.0.0] — YYYY-MM-DD   ← MAJOR bump

### Changed (BREAKING)
- [Description] — [migration guide link]
```
