---
id: plan-[domain]-[NNN]
title: "[Feature/Epic Name] — Implementation Plan"
type: plan
status: draft
version: 1.0.0
authors:
  - name: "[Author Name]"
    email: "[author@example.com]"
created: "[YYYY-MM-DD]"
updated: "[YYYY-MM-DD]"
depends_on:
  - req-[NNN]
  - api-[domain]-[NNN]
  - schema-[entity]-[NNN]
---

# Implementation Plan — [Feature/Epic Name]

---

## Scope

| Item | Value |
|---|---|
| Epic | [Epic name and ticket ID] |
| Target release | [Version or sprint] |
| Mode | Greenfield / Legacy |
| Spec maturity | L[0-4] at start → L[0-4] at end |
| Team | [Names or roles] |

---

## Pre-conditions

Before this plan can start:

- [ ] `specs/mission.md` is at `status: approved`
- [ ] `specs/requirements.md` is at `status: approved`
- [ ] All specs listed in `depends_on` are at `status: approved`
- [ ] Architecture ADR written (if new pattern introduced)
- [ ] Conformance tooling is configured

---

## Vertical Slices

Each slice is independently shippable. Order matters — earlier slices unblock later ones.

### Slice 1 — [Slice Name] (Foundation)

**Description**: [What this slice delivers end-to-end]
**Blocked by**: None
**Blocks**: Slices 2, 3

| Task | Layer | Spec Reference | Estimate | Owner |
|---|---|---|---|---|
| Write JSON Schema for [entity] | Spec | schema-[entity]-[NNN] | [Xh] | [Name] |
| Generate TypeScript types | Tooling | schema-[entity]-[NNN] | [Xh] | [Name] |
| Write DB migration | Data | schema-[entity]-[NNN] | [Xh] | [Name] |
| Write repository / data access | Data | schema-[entity]-[NNN] | [Xh] | [Name] |
| Write conformance test (failing) | Test | api-[domain]-[NNN] | [Xh] | [Name] |
| Implement [domain] service | Logic | req-[NNN] FR-001 | [Xh] | [Name] |
| Implement [endpoint] controller | API | api-[domain]-[NNN] | [Xh] | [Name] |
| Validate: all gate checks pass | QA | — | [Xh] | [Name] |

**Acceptance**: All gate checks pass. Slice 1 is deployed to staging.

---

### Slice 2 — [Slice Name]

**Description**: [What this slice adds]
**Blocked by**: Slice 1

| Task | Layer | Spec Reference | Estimate | Owner |
|---|---|---|---|---|
| [Task] | [Layer] | [Spec] | [Xh] | [Name] |

---

### Slice 3 — [Slice Name]

**Description**: [What this slice adds]
**Blocked by**: Slices 1 and 2

| Task | Layer | Spec Reference | Estimate | Owner |
|---|---|---|---|---|
| [Task] | [Layer] | [Spec] | [Xh] | [Name] |

---

## Task Order Within a Slice

For each slice, tasks must be executed in this order:

```
1. Spec confirmed at status: approved
2. Types generated from spec schemas
3. Database migration written and tested
4. Conformance test written (must fail — implementation missing)
5. Repository / data access layer implemented
6. Business logic implemented
7. API controller implemented
8. Conformance test passes
9. All existing tests still pass
10. Spec promoted to status: implemented
11. Gate check passes (G1 through G7)
12. PR opened with checklist
```

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| [Risk description] | High/Med/Low | High/Med/Low | [Mitigation strategy] |
| Spec gap discovered during implementation | Medium | Medium | Follow spec gap protocol; estimate 1 day buffer per slice |
| External dependency unavailable | Low | High | Mock the dependency in tests; use Pact contract |

---

## Definition of Done

The epic is done when:

- [ ] All slices are deployed to production
- [ ] All specs are at `status: validated`
- [ ] No open spec debt items at High or Critical priority
- [ ] CHANGELOG.md updated with spec references
- [ ] Performance gate passes (p95 meets SLO)
- [ ] Security gate passes
- [ ] Release tag created with migration guide (if MAJOR)
- [ ] SPEC-INDEX.md updated

---

## Rollback Plan

If any slice causes a regression in production:

1. Identify the failing gate
2. Revert the PR for the affected slice
3. Restore the previous spec status
4. Document the rollback in `specs/spec-debt.md` with priority and target fix date
