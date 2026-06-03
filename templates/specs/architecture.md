---
id: arch-[domain]-[NNN]
title: "[Project/Feature Name] — Architecture Document"
type: architecture
status: draft
version: 1.0.0
authors:
  - name: "[Author Name]"
    email: "[author@example.com]"
created: "[YYYY-MM-DD]"
updated: "[YYYY-MM-DD]"
depends_on:
  - req-[NNN]
  - mission-[NNN]
---

# Architecture — [Project/Feature Name]

> This document is derived from the approved specs. Every decision references the spec that drove it.

---

## C4 Level 1 — System Context

```
┌─────────────────────────────────────────────────────────────┐
│                        System Context                       │
│                                                             │
│   [External User]           [External System]               │
│         │                         │                         │
│         ▼                         ▼                         │
│   ┌─────────────────────────────────────┐                   │
│   │                                     │                   │
│   │         [System Name]               │                   │
│   │   [One-line system description]     │                   │
│   │                                     │                   │
│   └─────────────────────────────────────┘                   │
│              │                  │                           │
│              ▼                  ▼                           │
│       [Database]         [Third-party API]                  │
└─────────────────────────────────────────────────────────────┘
```

**System description**: [What the system does, who uses it, key external dependencies]

---

## C4 Level 2 — Container Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     [System Name]                           │
│                                                             │
│  [Browser / Mobile]                                         │
│         │ HTTPS                                             │
│         ▼                                                   │
│  ┌──────────────┐    REST/JSON    ┌──────────────┐          │
│  │  Web App     │ ─────────────► │  API Server  │          │
│  │  [Next.js]   │                │  [Fastify]   │          │
│  └──────────────┘                └──────┬───────┘          │
│                                         │                   │
│                              ┌──────────┼──────────┐        │
│                              ▼          ▼          ▼        │
│                         ┌──────┐  ┌──────┐  ┌──────┐       │
│                         │  DB  │  │Cache │  │Queue │       │
│                         │[PG]  │  │[Redis│  │[BullMQ│      │
│                         └──────┘  └──────┘  └──────┘       │
└─────────────────────────────────────────────────────────────┘
```

### Containers

| Container | Technology | Responsibility | Spec Reference |
|---|---|---|---|
| Web App | [e.g., Next.js 15] | Server-side rendering, client-side interactivity | — |
| API Server | [e.g., Fastify 5] | Business logic, data persistence | specs/api/*.openapi.yaml |
| Database | [e.g., PostgreSQL 16] | Persistent data storage | specs/schemas/*.schema.json |
| Cache | [e.g., Redis 7] | Session storage, rate limiting, hot data | — |
| Message Queue | [e.g., BullMQ] | Async job processing | specs/events/*.asyncapi.yaml |

---

## Data Model

Derived from JSON Schema contracts in `specs/schemas/`.

```
[Entity A] (1) ──────── (N) [Entity B]
     │                           │
     └──────── (N) [Entity C] ───┘

Entity A
├── id: uuid (PK)
├── name: varchar(100)
├── status: enum
├── ownerId: uuid (FK → users.id)
├── createdAt: timestamptz
└── updatedAt: timestamptz

Entity B
├── id: uuid (PK)
├── entityAId: uuid (FK → entity_a.id)
├── ...
```

**Database constraints** (derived from schema `required` and `format` fields):
- All PKs are UUID v4 (generated at application layer)
- All timestamps are UTC (stored as `timestamptz`)
- `NOT NULL` on all required schema fields
- `CHECK` constraints for enum values

---

## API Design

Derived from OpenAPI contracts in `specs/api/`.

### Endpoint Map

| Method | Path | Operation | Auth | Spec |
|---|---|---|---|---|
| GET | /api/v1/[resources] | list[Resources] | Bearer JWT | api-[domain]-[NNN] |
| POST | /api/v1/[resources] | create[Resource] | Bearer JWT | api-[domain]-[NNN] |
| GET | /api/v1/[resources]/{id} | get[Resource]ById | Bearer JWT | api-[domain]-[NNN] |
| PATCH | /api/v1/[resources]/{id} | update[Resource] | Bearer JWT | api-[domain]-[NNN] |
| DELETE | /api/v1/[resources]/{id} | delete[Resource] | Bearer JWT | api-[domain]-[NNN] |

### Auth Architecture

[Describe the auth flow. Reference ADR if a decision was made.]

```
Client → POST /auth/token → Auth Service → JWT issued
Client → GET /resources (Bearer JWT) → API Server → JWT validated → Response
```

### Error Handling Architecture

All errors use the standard error envelope (defined in specs/api/*.openapi.yaml):
```json
{ "error": { "code": "ERROR_CODE", "message": "...", "requestId": "uuid" } }
```

---

## Module Structure

Application source code organization derived from the domain model:

```
src/
├── modules/
│   └── [domain]/
│       ├── [entity].schema.ts      # Types generated from JSON Schema
│       ├── [entity].repository.ts  # Data access (implements interface)
│       ├── [entity].service.ts     # Business logic
│       ├── [entity].controller.ts  # HTTP handler (maps to OpenAPI operationIds)
│       └── [entity].test.ts        # Unit + conformance tests
├── shared/
│   ├── errors.ts                   # Error types matching error envelope
│   ├── middleware/                 # Auth, rate limit, request ID
│   └── types/                     # Generated from specs
├── infrastructure/
│   ├── database.ts                 # DB connection
│   └── migrations/                 # Schema migrations
└── app.ts                          # Server bootstrap
```

---

## Observability Architecture

Derived from `core-observability` rules and `specs/slos/*.slo.yaml`.

### Structured Log Format

```json
{
  "timestamp": "2024-01-15T10:00:00.000Z",
  "level": "info",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "traceId": "abc123",
  "spanId": "def456",
  "service": "[service-name]",
  "version": "1.0.0",
  "message": "Request completed",
  "http": {
    "method": "GET",
    "path": "/api/v1/resources",
    "status": 200,
    "durationMs": 45
  }
}
```

### Metrics (RED Method)
- **Rate**: requests/second per endpoint
- **Errors**: error rate per endpoint (4xx, 5xx)
- **Duration**: p50, p95, p99 per endpoint

---

## Architecture Decisions

| ADR | Title | Status | Impact |
|---|---|---|---|
| [ADR-001](specs/decisions/ADR-001-[title].md) | [Title] | Accepted | [Impact] |
| [ADR-002](specs/decisions/ADR-002-[title].md) | [Title] | Accepted | [Impact] |

---

## Open Architecture Questions

Questions that require an ADR before implementation:

1. [Question — who decides, deadline?]
2. [Question — who decides, deadline?]
