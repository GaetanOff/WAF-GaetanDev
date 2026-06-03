# Bug Fix Workflow

A bug is a spec violation. This workflow ensures every bug fix produces a spec improvement, not just a code patch.

---

## The Core Principle

Before fixing any bug, answer: **which spec does this bug violate?**
- If a spec exists: the bug is a deviation from contract → fix the code
- If no spec exists: the bug reveals a missing contract → write the spec first, then fix the code

---

## Step 1 — Bug Discovery

**Collect**:
1. Observed behavior (what the system does)
2. Expected behavior (what it should do according to the spec)
3. Exact reproduction steps
4. Affected spec (if any)

**Agent prompt**:
```
"Bug reported: [description]

Apply the SDD debugging decision tree:
1. Find which spec defines expected behavior for this scenario
2. If no spec: write the spec of expected behavior first (status: draft)
3. Write a failing test that reproduces the bug
Do NOT fix the code yet. Report which spec applies (or that it's missing)."
```

---

## Step 2 — Reproduction Test

Before any fix, write a failing test that documents the bug.

**Failing test structure**:
```typescript
// Bug: [description]
// Spec: [spec-id, link]
// Reproduction: [exact steps]

test("[feature]: [expected behavior] — regression test", async () => {
  // Arrange: set up the conditions that trigger the bug
  // ...

  // Act: trigger the buggy behavior
  // ...

  // Assert: what the spec says should happen (currently fails)
  expect(response.status).toBe(400);          // spec says 400, bug returns 200
  expect(response.body.error.code).toBe("VALIDATION_ERROR");
});
```

The test must fail before the fix and pass after. If it passes before the fix, the reproduction is wrong.

---

## Step 3 — Decision: Code Bug or Spec Bug?

```
Test is failing correctly
         │
         ▼
Is the spec correct for this scenario?
         │
    YES  │  NO (spec is wrong or ambiguous)
         │   └─► Update spec (requires review → approval)
         ▼       Then rerun this workflow
Does the code match the spec?
         │
   YES  ─► The test is wrong → fix the test
         │
   NO   ─► Code Bug → proceed to fix
```

---

## Step 4 — Fix

Implement the minimal fix that makes the reproduction test pass without breaking any other test.

**Agent prompt**:
```
"Fix the bug: [description].

The reproduction test is at [test/path].
The spec that defines correct behavior is @specs/[path].

Rules:
- Fix only what the spec says is wrong
- Do not refactor unrelated code
- Do not change the spec unless the spec itself was wrong (in that case get it approved first)
- Run the full test suite after the fix — report any new failures"
```

---

## Step 5 — Add Gherkin Scenario

Every confirmed bug must become a Gherkin scenario to prevent regression.

```gherkin
Scenario: [Feature] — [Bug description as expected behavior]
  # Regression test for bug [BUG-ID] — [link]
  Given [state that triggered the bug]
  When [action that triggered the bug]
  Then [correct response per spec]
  And [no data corruption / state is consistent]
```

Add this to `specs/features/[feature].feature` with `status: approved` (bugs are immediate spec additions).

---

## Step 6 — Validation & Changelog

```bash
# Must all pass
npm run test:conformance
npm run test:behavior   # New scenario must now pass
```

**Changelog entry**:
```markdown
### Fixed
- [Feature]: [Description of what was broken and what the correct behavior is]
  Regression test added. (spec: feat-[domain]-[NNN])
```

---

## Common Bug Categories

| Category | Spec Type | Action |
|---|---|---|
| Wrong HTTP status code | OpenAPI | Fix code to return correct status; or fix spec if the old one was wrong |
| Missing required field in response | JSON Schema | Fix code; or add field to spec if intentionally missing |
| No 401 on protected endpoint | OpenAPI securityScheme | Fix auth middleware |
| Validation not applied | OpenAPI requestBody schema | Fix validation layer |
| Incorrect error code | OpenAPI error responses | Fix code to return correct error code |
| Behavior not matching Gherkin | Gherkin feature file | Fix code; or update scenario if requirement changed |
