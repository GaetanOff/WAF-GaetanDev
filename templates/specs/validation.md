---
id: validation-[domain]-[NNN]
title: "[Feature/Epic Name] — Validation Report"
type: validation
status: draft
version: 1.0.0
authors:
  - name: "[Author Name]"
    email: "[author@example.com]"
created: "[YYYY-MM-DD]"
updated: "[YYYY-MM-DD]"
depends_on:
  - api-[domain]-[NNN]
  - schema-[entity]-[NNN]
  - feat-[domain]-[NNN]
---

# Validation Report — [Feature/Epic Name]

**Environment**: Staging / Production
**Release target**: [v.X.Y.Z]
**Validated by**: [Name(s)]
**Validation date**: [YYYY-MM-DD]

---

## Gate Results Summary

| Gate | Status | Details |
|---|---|---|
| G1 — Spec Lint | ✅ PASS / ❌ FAIL | [spec:lint exit code] |
| G2 — Type Check | ✅ PASS / ❌ FAIL | [tsc --noEmit exit code] |
| G3 — API Conformance | ✅ PASS / ❌ FAIL | [dredd/prism result] |
| G4 — Behavior (Gherkin) | ✅ PASS / ❌ FAIL | [cucumber result] |
| G5 — Security | ✅ PASS / ❌ FAIL | [audit result] |
| G6 — Performance | ✅ PASS / ❌ FAIL | [p95 latency vs SLO] |
| G7 — PR Checklist | ✅ PASS / ❌ FAIL | [reviewer sign-off] |

**Overall**: ✅ RELEASE READY / ❌ BLOCKED — [reason]

---

## Spec Coverage

| Spec | Type | Status Before | Status After | All Tests Pass |
|---|---|---|---|---|
| [api-domain-NNN] | OpenAPI | implemented | validated | ✅ Yes / ❌ No |
| [schema-entity-NNN] | JSON Schema | implemented | validated | ✅ Yes / ❌ No |
| [feat-domain-NNN] | Gherkin | implemented | validated | ✅ Yes / ❌ No |

---

## Gate 1 — Spec Lint

```
$ npm run spec:lint

Result: [PASS / FAIL]
Errors: [N]
Warnings: [N]

[Paste relevant output if FAIL]
```

---

## Gate 2 — Type Check

```
$ npm run typecheck

Result: [PASS / FAIL]
Errors: [N]

[Paste relevant output if FAIL]
```

---

## Gate 3 — API Conformance

```
$ npm run test:conformance

Endpoints tested: [N] / [total in spec]
Pass: [N]
Fail: [N]

Failed endpoints:
- [METHOD /path] — [reason]

[Paste dredd/prism summary]
```

---

## Gate 4 — Behavior (Gherkin)

```
$ npm run test:behavior

Scenarios: [total]
Passed:    [N]
Failed:    [N]
Skipped:   [N] (@wip)

Failed scenarios:
- [Feature file:line] — [reason]
```

---

## Gate 5 — Security

```
$ npm run security:audit

Hardcoded secrets: [NONE / LIST]
Dependency vulnerabilities (high+): [N]
SAST findings (high+): [N]
Auth enforcement check: [PASS / FAIL]
```

---

## Gate 6 — Performance

```
$ npm run test:perf

Environment: staging
Load: [X] concurrent users, [Y] req/s

Endpoint           | p50   | p95   | p99   | SLO    | Status
─────────────────────────────────────────────────────────────────
GET  /resources    | 24ms  | 89ms  | 180ms | 200ms  | ✅ PASS
POST /resources    | 45ms  | 190ms | 420ms | 500ms  | ✅ PASS
GET  /resources/:id| 12ms  | 45ms  | 90ms  | 200ms  | ✅ PASS
```

---

## Spec Debt Resolved

Spec debt items resolved by this release:

| ID | Description | Resolved How |
|---|---|---|
| SD-[NNN] | [Description] | [How it was fixed] |

---

## Open Issues

Issues found during validation that do not block release:

| Priority | Description | Spec Reference | Target Fix |
|---|---|---|---|
| Low | [Issue] | [Spec] | [Sprint/version] |

---

## Sign-off

By signing off, the reviewer confirms that all blocking gates have passed and the release is approved.

| Role | Name | Date | Signature |
|---|---|---|---|
| Developer | [Name] | [YYYY-MM-DD] | ☐ |
| Reviewer | [Name] | [YYYY-MM-DD] | ☐ |
| Lead / Tech Lead | [Name] | [YYYY-MM-DD] | ☐ |

---

## Post-Release Checklist

- [ ] Spec statuses promoted to `validated` in all spec files
- [ ] SPEC-INDEX.md updated
- [ ] CHANGELOG.md [Unreleased] renamed to [X.Y.Z] — YYYY-MM-DD
- [ ] Git tag created: `v[X.Y.Z]`
- [ ] Deprecated specs marked with sunset date
- [ ] Monitoring alerts confirmed active
- [ ] On-call team notified of deployment
