---
id: adr-[domain]-[NNN]
title: "[Decision Title]"
type: adr
status: draft
version: 1.0.0
authors:
  - name: "[Author Name]"
    email: "[author@example.com]"
created: "[YYYY-MM-DD]"
updated: "[YYYY-MM-DD]"
depends_on: []
---

# ADR-[NNN] — [Decision Title]

**Date**: [YYYY-MM-DD]
**Status**: Proposed | Accepted | Deprecated | Superseded by [ADR-NNN]
**Deciders**: [List of people who reviewed and approved]

---

## Context

[Describe the situation that makes this decision necessary. Include:]
- [The current state of the system]
- [The problem or requirement driving this decision]
- [Any constraints that narrow the solution space]
- [Reference to the spec(s) that drove this decision]

**Related specs**: [specs/api/[domain].openapi.yaml], [specs/schemas/[entity].schema.json]

---

## Decision Drivers

The factors that matter most when evaluating options:

- **[Driver 1]**: [Why this matters — e.g., "Simplicity: we want to minimize operational overhead"]
- **[Driver 2]**: [Why this matters — e.g., "Consistency: this must align with existing auth patterns"]
- **[Driver 3]**: [Why this matters — e.g., "Performance: p95 latency must remain < 200ms"]

---

## Options Considered

### Option A — [Name]

**Description**: [How this option works]

**Pros**:
- [Specific benefit, tied to a decision driver if possible]
- [Another benefit]

**Cons**:
- [Specific drawback, tied to a decision driver]
- [Another drawback]

**Impact on specs**:
- [Does this option require changes to existing API contracts?]
- [Does it introduce new schema fields?]

---

### Option B — [Name]

**Description**: [How this option works]

**Pros**:
- [Benefit]

**Cons**:
- [Drawback]

**Impact on specs**:
- [Spec impact]

---

### Option C — [Name] (optional)

**Description**: [How this option works]

**Pros**:
- [Benefit]

**Cons**:
- [Drawback]

---

## Decision

**Chosen option**: Option [A/B/C] — "[Name]"

**Rationale**: [Explain why this option was chosen over the alternatives. Reference the decision drivers. Be specific about trade-offs accepted.]

[Example: "We chose Option B because it aligns with our existing JWT auth pattern (driver: consistency) and adds no new infrastructure. The trade-off is slightly higher token size, which is acceptable given our 10KB payload limit."]

---

## Consequences

### Positive
- [What becomes easier, better, or cheaper as a result]
- [What risks are eliminated]

### Negative
- [What becomes harder, slower, or more expensive as a result]
- [What new risks are introduced]
- [What is now off-limits due to this decision]

### Neutral
- [Changes that are neither positive nor negative — but noteworthy]

---

## Spec Impact

List every specification artifact that must be updated as a result of this decision:

| Spec | Change Required | Breaking | Version Bump |
|---|---|---|---|
| [specs/api/domain.openapi.yaml] | [e.g., Add securityScheme: BearerAuth to all protected endpoints] | No | minor |
| [specs/schemas/user.schema.json] | [e.g., Add `roles` field] | No | minor |
| [None] | — | — | — |

---

## Implementation Notes

[Practical notes for the developer implementing this decision:]

- [Specific library or pattern to use]
- [Configuration required]
- [Migration required — and which migration file to create]
- [Tests required — link to Gherkin scenarios if applicable]

---

## Review Notes

[Record key points from the review discussion. Objections raised and how they were resolved.]

- **[Reviewer Name]** ([Date]): [Concern or question and resolution]

---

## Links

- [Link to related ADR if this supersedes or extends one]
- [Link to RFC or external reference that informed this decision]
- [Link to ticket or issue that triggered this decision]
