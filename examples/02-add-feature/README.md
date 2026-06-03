# Example 02 — Adding a Feature to an Existing Project

This example shows how to add a "task labels" feature to the task management API built in Example 01. The project has L3 spec maturity (all specs exist, conformance tested in CI).

**Mode**: Legacy (feature addition to existing project)
**Change type**: Additive (non-breaking, minor version bump)

---

## The Request

> "Add labels to tasks. Users should be able to tag tasks with labels and filter tasks by label."

---

## Step 1 — Discovery (even for small features)

**Agent prompt**:
```
"I want to add labels to tasks.
Before writing any spec, check @specs/ for existing contracts.
Then ask only the discovery questions that are unclear from the existing specs."
```

**Agent response**:
> I reviewed the existing specs. The Task schema does not include a `labels` field. The `GET /tasks` endpoint has `status` filter but no label filter. I need answers to:
> 1. **WHAT**: Are labels free-form strings or from a predefined set? Max labels per task?
> 2. **WHEN**: Can you filter by multiple labels (AND or OR logic)?
> 3. **WHY WRONG**: What happens if an invalid label is provided?

**Answers**:
1. Free-form strings, lowercase, max 20 chars, max 5 labels per task
2. Filter is OR logic (tasks matching ANY of the provided labels)
3. Invalid label (uppercase, >20 chars) → 400 VALIDATION_ERROR

---

## Step 2 — Delta Spec (additive, non-breaking)

**Changes to existing specs**:

```yaml
# specs/schemas/task.schema.json — ADD optional labels field

"labels": {
  "type": "array",
  "items": {
    "type": "string",
    "minLength": 1,
    "maxLength": 20,
    "pattern": "^[a-z0-9-]+$"
  },
  "maxItems": 5,
  "uniqueItems": true,
  "default": [],
  "description": "Optional list of labels. Lowercase alphanumeric with hyphens."
}
```

```yaml
# specs/api/tasks.openapi.yaml — ADD query param to listTasks

parameters:
  - name: labels
    in: query
    description: "Filter by labels (OR logic). Comma-separated."
    schema:
      type: array
      items:
        type: string
      maxItems: 5
    style: form
    explode: false
```

**New Gherkin scenarios**:
```gherkin
Scenario: Create a task with labels
  Given I am authenticated
  When I create a task with labels ["work", "urgent"]
  Then the response status is 201
  And the task has labels ["work", "urgent"]

Scenario: Filter tasks by label
  Given I have tasks with labels ["work", "personal", "urgent"]
  When I list tasks with filter labels=["work","urgent"]
  Then only tasks with label "work" OR "urgent" are returned

Scenario: Label with uppercase rejected
  Given I am authenticated
  When I create a task with label "URGENT"
  Then the response status is 400
  And the error code is "VALIDATION_ERROR"
```

**Version impact**: Minor (new optional field, new query param) → bump from v1.0.0 to v1.1.0.

---

## Step 3 — Spec Review

Review checklist confirmed:
- ✅ New `labels` field is optional (not breaking for existing clients)
- ✅ Pattern constraint is clear and testable
- ✅ Filter is additive (existing filter still works)
- ✅ No existing spec contradicted
- ✅ Version bump is `minor` (correct)
- Specs promoted to `status: approved`

---

## Step 4 — Implementation

**Agent prompt**:
```
"Implement labels for tasks against the approved delta spec.
@specs/schemas/task.schema.json — new labels field (v1.1.0)
@specs/api/tasks.openapi.yaml — new labels filter on listTasks (v1.1.0)
@specs/features/tasks.feature — new label scenarios

Implementation order:
1. Generate updated TypeScript types
2. Write failing conformance tests for new scenarios
3. Add labels column to tasks table (migration)
4. Update repository to persist and query labels
5. Update service to validate labels
6. Update controllers to pass labels filter
7. Confirm all existing tests still pass
8. Confirm new tests pass"
```

**DB Migration** (additive, reversible):
```sql
-- up
ALTER TABLE tasks ADD COLUMN labels TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX tasks_labels_gin ON tasks USING gin(labels);

-- down
DROP INDEX tasks_labels_gin;
ALTER TABLE tasks DROP COLUMN labels;
```

---

## Step 5 — Gate Check & Release

```bash
npm run spec:lint       # ✅ 0 errors
npm run typecheck       # ✅ 0 errors
npm run test:conformance # ✅ 7/7 endpoints pass (including new label scenarios)
npm run test:behavior    # ✅ 15/15 scenarios pass (12 old + 3 new)
```

**CHANGELOG entry**:
```markdown
## [1.1.0] — 2024-03-25

### Added
- Task labels: tasks now support up to 5 lowercase labels (spec: schema-task-001 v1.1.0)
- `GET /tasks?labels=` filter: filter tasks by labels using OR logic (spec: api-tasks-001 v1.1.0)
```

---

## What SDD Prevented

1. **Prevented schema drift**: The label pattern (`^[a-z0-9-]+$`) was defined in the spec before implementation, not inferred from code.
2. **Prevented breaking change**: Adding `labels` as optional preserved backward compatibility — confirmed by spec review before writing a line of code.
3. **Prevented missing index**: The GIN index on labels was included in the spec review discussion, not discovered after a slow query in production.
