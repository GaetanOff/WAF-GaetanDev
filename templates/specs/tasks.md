---
id: tasks-[domain]-[NNN]
title: "[Feature/Sprint Name] — Task List"
type: tasks
status: draft
version: 1.0.0
sprint: "[Sprint name or number]"
authors:
  - name: "[Author Name]"
    email: "[author@example.com]"
created: "[YYYY-MM-DD]"
updated: "[YYYY-MM-DD]"
depends_on:
  - plan-[domain]-[NNN]
---

# Tasks — [Feature/Sprint Name]

---

## Current Sprint Goal

[One sentence: what does success look like at the end of this sprint?]

---

## Spec Tasks

Spec work always precedes implementation. These tasks must be completed first.

| # | Task | Spec Output | Assignee | Status | Notes |
|---|---|---|---|---|---|
| S-001 | Write JSON Schema for [entity] | specs/schemas/[entity].schema.json | [Name] | 🔲 Todo | |
| S-002 | Write OpenAPI spec for [domain] | specs/api/[domain].openapi.yaml | [Name] | 🔲 Todo | |
| S-003 | Write Gherkin scenarios for [feature] | specs/features/[feature].feature | [Name] | 🔲 Todo | |
| S-004 | Spec review + approval | status: approved | [Name] | 🔲 Todo | Blocked by S-001, S-002, S-003 |

---

## Implementation Tasks

Only start after related specs are at `status: approved`.

| # | Task | Spec Ref | Estimate | Assignee | Status | Notes |
|---|---|---|---|---|---|---|
| I-001 | Generate TypeScript types | schema-[entity]-[NNN] | 0.5h | [Name] | 🔲 Todo | |
| I-002 | Write DB migration | schema-[entity]-[NNN] | 1h | [Name] | 🔲 Todo | |
| I-003 | Write failing conformance test | api-[domain]-[NNN] | 1h | [Name] | 🔲 Todo | |
| I-004 | Implement repository layer | schema-[entity]-[NNN] | 2h | [Name] | 🔲 Todo | Blocked by I-002 |
| I-005 | Implement service layer | req-[NNN] FR-001 | 3h | [Name] | 🔲 Todo | Blocked by I-004 |
| I-006 | Implement controller layer | api-[domain]-[NNN] | 2h | [Name] | 🔲 Todo | Blocked by I-005 |
| I-007 | All gate checks pass | — | 1h | [Name] | 🔲 Todo | Blocked by I-006 |

---

## Validation Tasks

| # | Task | Spec Ref | Assignee | Status | Notes |
|---|---|---|---|---|---|
| V-001 | Run full gate check on staging | — | [Name] | 🔲 Todo | |
| V-002 | Promote spec statuses to `validated` | All specs | [Name] | 🔲 Todo | Blocked by V-001 |
| V-003 | Update CHANGELOG.md | — | [Name] | 🔲 Todo | |
| V-004 | Update SPEC-INDEX.md | — | [Name] | 🔲 Todo | |
| V-005 | Create release tag v[X.Y.Z] | — | [Name] | 🔲 Todo | Blocked by V-001-V-004 |

---

## Blocked / On Hold

| Task | Blocked By | ETA | Notes |
|---|---|---|---|
| [Task] | [Blocker — person, decision, external dependency] | [YYYY-MM-DD] | [Notes] |

---

## Spec Debt Identified This Sprint

| ID | Description | Spec | Priority | Due Sprint |
|---|---|---|---|---|
| SD-[NNN] | [Description of gap] | [Spec ref] | High/Med/Low | [Sprint] |

---

## Status Legend

| Symbol | Meaning |
|---|---|
| 🔲 | Todo |
| 🔄 | In Progress |
| 👀 | In Review |
| ✅ | Done |
| 🚫 | Blocked |
| ⏸️ | On Hold |
