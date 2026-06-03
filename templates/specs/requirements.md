---
id: req-000
title: [Feature/Project Name] — Requirements
type: requirements
status: draft
version: 1.0.0
authors:
  - name: [Author Name]
    email: [author@example.com]
created: [YYYY-MM-DD]
updated: [YYYY-MM-DD]
depends_on:
  - mission-000
---

# Requirements — [Feature/Project Name]

---

## Functional Requirements

### FR-001 — [Requirement Title]

**Priority**: Must Have | Should Have | Nice to Have
**Actor**: [Who triggers or benefits]
**Description**: [Precise description of the required behavior]

**Acceptance Criteria**:

```gherkin
Given [initial context]
When [action or event]
Then [expected outcome]
And [additional expected outcome]
```

**Error Cases**:

```gherkin
Given [context]
When [invalid action]
Then [error response]
And [system state is unchanged / rolled back]
```

---

### FR-002 — [Requirement Title]

**Priority**: Must Have
**Actor**: [Who]
**Description**: [Description]

**Acceptance Criteria**:

```gherkin
Given [context]
When [action]
Then [outcome]
```

---

## Non-Functional Requirements

### NFR-001 — Performance

| Metric | Threshold | Measurement | SLO Reference |
|---|---|---|---|
| API response time (p95) | < [X]ms | Load test | specs/slos/api.slo.yaml |
| API error rate | < [X]% | Monitoring | specs/slos/api.slo.yaml |
| Data processing throughput | > [X] records/sec | Benchmark | - |
| Availability | [X]% uptime | Synthetic monitoring | specs/slos/api.slo.yaml |

### NFR-002 — Security

- [ ] All endpoints require authentication unless explicitly marked as public
- [ ] Input validated against JSON Schema on every request
- [ ] PII fields: [list fields] — must be encrypted at rest, never logged
- [ ] Compliance requirement: [GDPR / HIPAA / SOC2 / None]
- [ ] Rate limiting: [X] requests per [window] per [actor]

### NFR-003 — Scalability

- **Expected load**: [X] concurrent users, [Y] requests/second at peak
- **Data volume**: [X] records at launch, growing [Y]% per [period]
- **Geographic distribution**: [regions or single-region]

### NFR-004 — Availability & Reliability

- **Target uptime**: [X]%
- **Recovery Time Objective (RTO)**: [X minutes/hours]
- **Recovery Point Objective (RPO)**: [X minutes/hours]
- **Failure mode**: [graceful degradation / fail-fast / circuit breaker]

### NFR-005 — Accessibility (Frontend)

- WCAG 2.1 Level AA compliance
- Keyboard navigation for all interactive elements
- Screen reader support for all content
- Touch targets ≥ 44px on mobile

---

## Data Requirements

### Entities

List every entity this feature creates, reads, updates, or deletes.

| Entity | Operations | Source of Truth | Spec Reference |
|---|---|---|---|
| [EntityName] | Create, Read, Update | [DB / external API] | specs/schemas/[entity].schema.json |
| [EntityName] | Read | [External system] | specs/contracts/[provider].pact.json |

### Data Retention

| Data Type | Retention Period | Deletion Policy |
|---|---|---|
| [Data] | [Period] | [Hard delete / Soft delete / Archive] |
| [PII Data] | [Period — per GDPR/HIPAA] | [Right to erasure protocol] |

---

## Integration Requirements

| Integration | Type | Direction | Protocol | Auth |
|---|---|---|---|---|
| [Service Name] | External API | Outbound | REST | API Key |
| [Service Name] | Message Queue | Inbound | AMQP | mTLS |
| [Database] | Internal | Read/Write | SQL | Service account |

---

## Constraints & Dependencies

### Hard Dependencies (blockers)
- [ ] [Dependency] must be available before implementation starts
- [ ] [Other team / service] must deliver [X] first

### Soft Dependencies (assumptions)
- [ ] [Assumption about third-party behavior]
- [ ] [Assumption about data quality]

---

## Out of Scope

Explicitly excluded from this requirements document:

- [Feature or behavior explicitly not required]
- [Edge case that will not be handled in this version]
- [Integration that is deferred]

---

## Traceability Matrix

| Requirement | Spec | Test | Implementation |
|---|---|---|---|
| FR-001 | specs/features/[feature].feature | test/[feature].test.ts | src/[module]/[file].ts |
| FR-002 | specs/api/[domain].openapi.yaml | test/conformance/[api].test.ts | src/[module]/[file].ts |
| NFR-001 | specs/slos/api.slo.yaml | test/perf/[api].k6.js | - |
