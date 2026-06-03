# Example 03 — Legacy Refactor via Specs

This example shows how to safely refactor a legacy module using the SDD workflow. The legacy system has no specs, no tests, and has been accumulating debt for 2 years.

**Mode**: Legacy (retro-spec → gap analysis → delta spec → incremental refactor)
**Goal**: Refactor the `OrderProcessor` class without breaking existing behavior

---

## Starting Point

The legacy code looks like this:

```typescript
// src/orders/orderProcessor.ts — No tests, no spec, 450 lines

class OrderProcessor {
  async process(data: any) {       // ← `any` type
    if (!data.items) return false; // ← silent failure
    // ... 400 more lines of mixed concerns
    db.query("INSERT INTO orders VALUES (" + data.id + ")"); // ← SQL injection
    console.log("Order created"); // ← no structured logging
    return true;
  }
}
```

**Problems identified**:
- No spec for expected behavior
- `any` types everywhere
- Silent failures (returns false instead of throwing)
- SQL injection vulnerability
- Mixed concerns (validation, persistence, notification, pricing all in one class)
- No error codes — impossible to test specific failures

---

## Step 1 — Retro-Spec: Document Current Behavior

**Agent prompt**:
```
"Write retro-specs for @src/orders/orderProcessor.ts.
Describe CURRENT behavior as-is — do not improve or change anything.
1. JSON Schema for the Order entity (infer from code and any DB schema)
2. OpenAPI entry for any HTTP endpoints that call this processor
3. 3 Gherkin scenarios for the most critical behaviors
Mark everything as status: implemented.
Do not change any code."
```

**Result**:
```
specs/schemas/order.schema.json     (status: implemented, describes current shape)
specs/api/orders.openapi.yaml       (status: implemented, describes current API)
specs/features/order-processing.feature (status: implemented, 3 happy-path scenarios)
```

The retro-specs are deliberately imperfect — they document what the code does, including the bugs.

---

## Step 2 — Gap Analysis

**Agent prompt**:
```
"Analyze @src/orders/orderProcessor.ts against its retro-specs.
List:
1. Security vulnerabilities
2. Missing error cases (behaviors with no spec coverage)
3. Mixed concerns that should be separated
4. Performance issues
Do not propose solutions yet — just catalogue the problems."
```

**Gap report**:
| Issue | Category | Priority |
|---|---|---|
| SQL injection in `db.query(...)` | Security | Critical |
| Silent `return false` on missing items | Missing error spec | High |
| No 401/403 check before processing | Security | Critical |
| Pricing logic mixed with persistence | Design | Medium |
| No correlation ID in logs | Observability | Medium |
| `data.items` never validated against schema | Contract | High |

---

## Step 3 — Delta Specs (Target State)

**Agent prompt**:
```
"Write delta specs for the refactored OrderProcessor.
These describe the TARGET behavior (not current).
1. Updated JSON Schema with strict types and constraints
2. Updated OpenAPI with proper error responses (400, 401, 403, 422)
3. New Gherkin scenarios for error paths
4. ADR for splitting OrderProcessor into separate concerns
Mark all delta specs as status: draft."
```

**ADR written**: `specs/decisions/ADR-004-order-processor-separation.md`
Decision: Split `OrderProcessor` into `OrderValidator`, `PricingService`, `OrderRepository`, `OrderController`.

---

## Step 4 — Incremental Refactor (Slice by Slice)

### Slice 1 — Security Fixes (no behavior change)

```
Goal: Fix SQL injection + add auth check
Constraint: All retro-spec scenarios must still pass
```

**Agent prompt**:
```
"Refactor @src/orders/orderProcessor.ts — Slice 1: Security Only.
1. Replace raw SQL with parameterized queries (no behavior change)
2. Add auth check before processing (per security spec)
Run all retro-spec tests before and after. Report any differences."
```

### Slice 2 — Input Validation (behavior change — needs delta spec approved first)

```
Goal: Validate input against JSON Schema, return 400 with proper error code
Delta spec: specs/api/orders.openapi.yaml (400 response, VALIDATION_ERROR code)
```

**Agent prompt**:
```
"Refactor Slice 2: Input Validation.
Implement input validation against @specs/schemas/order.schema.json.
Return 400 VALIDATION_ERROR when validation fails (per delta spec).
Retro-spec tests must still pass (except the silent-failure behavior, 
which is now replaced by the proper 400 response per delta spec).
New delta-spec tests must pass."
```

### Slice 3 — Concern Separation (refactor, no behavior change)

```
Goal: Extract OrderValidator, PricingService, OrderRepository
Constraint: All existing tests must pass
```

---

## Step 5 — Spec Promotion

After each slice, update spec statuses:
- Retro-specs that changed → update + promote to `approved`
- Delta specs that are now implemented → promote to `implemented`
- After gate check passes → promote to `validated`

---

## What SDD Made Possible

1. **Safe refactor**: The retro-specs defined a contract net before any change. Every slice was validated against it.
2. **Prioritized security**: The gap analysis surfaced the SQL injection as Critical before any "clean code" work started.
3. **No behavior regression**: The conformance suite caught a change in error format between Slice 1 and the old retro-spec — prevented a silent breaking change to API consumers.
4. **Incremental delivery**: Each slice was independently deployable. No "big bang" refactor.

---

## Lessons Learned

- Writing retro-specs for a 450-line class took 2 hours. It uncovered 3 security issues immediately.
- The delta specs forced the team to explicitly decide: "is this behavior we want to keep?" — rather than preserving bugs by accident.
- The SQL injection was in production for 2 years. The retro-spec exercise found it in the first 30 minutes of analysis.
