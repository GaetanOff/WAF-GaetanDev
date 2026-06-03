# Example 04 — Bug Fix via Spec Reproduction

This example demonstrates the SDD bug fix workflow. A production bug is reported. Instead of patching code, we write a spec first, then fix the code.

**Mode**: Legacy (existing project with partial spec coverage)
**Bug type**: Incorrect HTTP status code + missing error case in spec

---

## The Bug Report

> "JIRA-1234: When creating a task with `dueDate` set to yesterday, the API returns 201 Created. But business logic should reject past due dates. Users are creating tasks with due dates that have already passed."

---

## Step 1 — Apply the SDD Debugging Decision Tree

**Agent prompt**:
```
"Bug: Creating a task with a past dueDate returns 201 Created instead of 400.
Apply the SDD debugging decision tree.
First, find what the spec says about past due dates.
Reference @specs/api/tasks.openapi.yaml and @specs/features/tasks.feature."
```

**Agent response**:
> I checked `specs/api/tasks.openapi.yaml` and `specs/features/tasks.feature`.
> 
> **Result: Spec Gap.** Neither the OpenAPI spec nor the Gherkin scenarios mention anything about past due dates. The `dueDate` field in the schema is defined as `format: date` with no minimum constraint.
> 
> This is a **missing spec** case, not a code bug. The code is doing what the spec allows. Before fixing the code, we need to write the spec.

---

## Step 2 — Write the Spec First

**Decision required**: Should past due dates be rejected? Or should they be allowed with a warning?

After stakeholder discussion: **Past due dates are rejected with 422 UNPROCESSABLE_ENTITY**. (Not 400 — because the request is syntactically valid but semantically invalid.)

**Agent prompt**:
```
"Update the spec to define behavior for past due dates.
1. Add a constraint to specs/schemas/task.schema.json: dueDate must be >= today (format: date)
   Note: this is a soft constraint (business rule) — use description, not JSON Schema format constraint
2. Add 422 response to POST /tasks in specs/api/tasks.openapi.yaml:
   error code: PAST_DUE_DATE, message: 'Due date must be today or in the future.'
3. Add a Gherkin scenario to specs/features/tasks.feature:
   'Creating a task with a past due date is rejected'
Status: draft on all changes. Do not modify any code."
```

**Result**:

```yaml
# specs/api/tasks.openapi.yaml — new 422 response on POST /tasks
"422":
  description: Semantically invalid request (business rule violation)
  content:
    application/json:
      schema:
        $ref: "#/components/schemas/ErrorResponse"
      example:
        error:
          code: "PAST_DUE_DATE"
          message: "Due date must be today or in the future."
          requestId: "123e4567-e89b-12d3-a456-426614174000"
```

```gherkin
# specs/features/tasks.feature — new scenario
Scenario: Creating a task with a past due date is rejected
  Given I am authenticated as "user@example.com"
  When I create a task with dueDate set to yesterday
  Then the response status is 422
  And the error code is "PAST_DUE_DATE"
  And no task is created in the database
```

**Spec review → approved**.

---

## Step 3 — Write the Reproduction Test

```typescript
// test/conformance/tasks-regression.test.ts
// Regression test for JIRA-1234
// Spec: api-tasks-001 v1.1.1 (POST /tasks, 422 PAST_DUE_DATE)

describe("POST /tasks — past due date validation", () => {
  it("rejects a task with a due date in the past", async () => {
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);

    const response = await request(app)
      .post("/api/v1/tasks")
      .set("Authorization", `Bearer ${validToken}`)
      .send({
        title: "Late task",
        dueDate: yesterday.toISOString().split("T")[0],
      });

    // This test FAILS before the fix (returns 201)
    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe("PAST_DUE_DATE");
  });
});
```

Test run result: **FAIL** (201 returned, expected 422). This confirms the reproduction is correct.

---

## Step 4 — Fix the Code

**Agent prompt**:
```
"Fix the bug for JIRA-1234.
The approved spec is @specs/api/tasks.openapi.yaml (POST /tasks, 422 PAST_DUE_DATE).
The reproduction test is at test/conformance/tasks-regression.test.ts.

Add dueDate validation to the task service:
- If dueDate is provided and is in the past, throw a PAST_DUE_DATE error
- The controller must return 422 for this error
- Do not change any other behavior
Run the full test suite after the fix."
```

**Fix applied**:
```typescript
// src/modules/tasks/task.service.ts

if (input.dueDate) {
  const today = new Date().toISOString().split("T")[0];
  if (input.dueDate < today) {
    throw new BusinessError("PAST_DUE_DATE", "Due date must be today or in the future.");
  }
}
```

---

## Step 5 — Validation

```bash
npm run test:conformance   # ✅ All endpoints pass (including new 422 scenario)
npm run test:behavior       # ✅ New Gherkin scenario passes
npm run spec:lint           # ✅ 0 errors
```

**CHANGELOG entry**:
```markdown
### Fixed
- Tasks: creating a task with a past due date now returns 422 PAST_DUE_DATE
  instead of silently accepting it. Regression test added. (spec: api-tasks-001 v1.1.1)
```

---

## Key Takeaways

1. **The spec was missing, not the code.** The code was doing what the spec allowed. Patching the code without updating the spec would have created invisible technical debt.
2. **422 vs 400 was a real decision.** The SDD workflow forced the team to think about HTTP semantics, not just "add a check."
3. **The reproduction test caught the fix immediately.** No ambiguity about whether the fix worked.
4. **The Gherkin scenario prevents recurrence.** Next time someone modifies task creation, this scenario will catch a regression.
5. **Version bump was `patch`** (v1.1.0 → v1.1.1) because the spec change added a missing constraint that didn't affect existing valid requests.
