---
id: mission-000
title: [Project Name] — Mission Statement
type: mission
status: draft
version: 1.0.0
authors:
  - name: [Author Name]
    email: [author@example.com]
created: [YYYY-MM-DD]
updated: [YYYY-MM-DD]
---

# Mission Statement — [Project Name]

> One sentence: what does this project do, for whom, and why does it matter?

---

## Problem Statement

**Context**
[Describe the current situation. What exists today? What is broken, missing, or inefficient? Include evidence if available: user quotes, metrics, incident reports.]

**Problem**
[The specific, bounded pain point this project solves. Be concrete. Avoid "improve user experience" — say what is broken and for whom.]

**Impact of Inaction**
[What happens if this problem is not solved? Who is affected, how often, what is the cost?]

---

## Solution Hypothesis

[The proposed solution direction. Not the implementation — the intent. One paragraph. This is a hypothesis, not a commitment.]

---

## Actors

| Actor | Type | Primary Goal | Notes |
|---|---|---|---|
| [Primary User] | Human — [role] | [What they want to achieve] | [Constraints, permissions] |
| [Secondary User] | Human — [role] | [What they want to achieve] | [Constraints, permissions] |
| [External System] | System | [What it provides or receives] | [Integration point] |
| [Background Job] | System | [What it processes] | [Async, scheduled, etc.] |

---

## Goals

### Must Achieve (Core Goals)
- [ ] [Specific, measurable goal 1]
- [ ] [Specific, measurable goal 2]
- [ ] [Specific, measurable goal 3]

### Should Achieve (Secondary Goals)
- [ ] [Goal that adds value but is not essential for v1]

### Nice to Have (Future Goals)
- [ ] [Goal for a future iteration]

---

## Non-Goals

Explicitly list what this project will NOT do. This is as important as the goals.

- **Out of scope**: [Feature or domain that is explicitly excluded and why]
- **Out of scope**: [Feature that may seem related but belongs elsewhere]
- **Out of scope**: [Future capability that is deferred to v2+]

---

## Success Criteria

How will we know the project succeeded? Measurable thresholds tied to goals.

| Goal | Success Metric | Measurement Method | Target |
|---|---|---|---|
| [Goal 1] | [Metric] | [How to measure] | [Threshold] |
| [Goal 2] | [Metric] | [How to measure] | [Threshold] |

---

## Constraints

### Technical Constraints
- [Existing system that must be integrated: name, version, protocol]
- [Performance requirement: latency, throughput, availability]
- [Deployment constraint: cloud provider, region, runtime]
- [Security/compliance requirement: GDPR, HIPAA, SOC2, PCI-DSS]

### Business Constraints
- **Deadline**: [Date or milestone]
- **Budget**: [Infrastructure cost ceiling if applicable]
- **Regulatory**: [Legal or compliance requirements]
- **Team**: [Relevant expertise gaps or dependencies]

---

## Assumptions

| ID | Assumption | Risk if Wrong | Resolution | Status |
|---|---|---|---|---|
| A-001 | [Assumption] | [Impact] | [How to resolve] | ⏳ Pending |
| A-002 | [Assumption] | [Impact] | [How to resolve] | ✅ Confirmed |

---

## Open Questions

Questions that must be answered before specs can be written. Each question becomes an assumption once answered.

1. [Question — who answers this?]
2. [Question — deadline for answer?]

---

## References

- [Link to product brief or PRD]
- [Link to user research or feedback]
- [Link to related ADRs]
- [Link to related specs]
