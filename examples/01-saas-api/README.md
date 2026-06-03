# Example 01 — Building a SaaS API from Scratch

This example walks through the complete SDD workflow for building a simple task management SaaS API (greenfield, REST, TypeScript + Fastify + PostgreSQL).

**Estimated time**: 2-4 hours for a senior dev following this workflow
**Mode**: Greenfield
**Stack**: TypeScript, Fastify, PostgreSQL, Prisma, Vitest, Dredd

---

## The Request

> "Build a task management API where users can create, list, update, and delete tasks."

Without SDD: a developer would immediately start coding. With SDD, we stop and start discovery.

---

## Phase 0 — Discovery

**Agent prompt sent**:
```
"I want to build a task management API.
Before any spec or code, ask the 5 minimum discovery questions.
Do not proceed until I answer them."
```

**Questions asked by the agent**:
1. **WHO** — What actor creates tasks? What system receives completed tasks?
2. **WHAT** — What fields does a task have? What does "completed" mean exactly?
3. **WHEN** — Can tasks have due dates? Can they be assigned to other users?
4. **WHY WRONG** — What happens if a task is created with a missing title? With an invalid due date?
5. **DONE** — What does a working API look like? Can I list tasks sorted by due date?

**Answers**:
1. Authenticated users create and manage their own tasks. No external system integration in v1.
2. Fields: title (required), description (optional), status (todo/in-progress/done), dueDate (optional ISO 8601).
3. Tasks belong to a single user. No assignment to others in v1.
4. Missing title → 400 VALIDATION_ERROR. Invalid date format → 400. No auth → 401.
5. Done = I can CRUD tasks and list them filtered by status.

**Artifacts created**:
- `specs/mission.md` → status: approved
- `specs/decisions/ADR-000-project-context.md` → status: accepted

---

## Phase 1 — Specification

**Step 1 — Data contract**

Agent prompt:
```
"Write the JSON Schema for Task at specs/schemas/task.schema.json.
Fields: id (uuid), title (string 1-200), description (string, optional, max 2000),
status (enum: todo|in-progress|done, default: todo),
dueDate (string, format: date, optional), ownerId (uuid), createdAt/updatedAt (date-time).
additionalProperties: false. Status: draft."
```

Result: `specs/schemas/task.schema.json` (status: draft → reviewed → approved)

**Step 2 — API contract**

Agent prompt:
```
"Write the OpenAPI 3.1 spec for the Tasks API at specs/api/tasks.openapi.yaml.
Operations: listTasks (GET /tasks), createTask (POST /tasks),
getTaskById (GET /tasks/{id}), updateTask (PATCH /tasks/{id}),
deleteTask (DELETE /tasks/{id}).
Use the standard error envelope. All endpoints require BearerAuth.
Include query params for listTasks: status (enum), page, pageSize.
Status: draft."
```

Result: `specs/api/tasks.openapi.yaml` (status: draft → reviewed → approved)

**Step 3 — Behavior specs**

Agent prompt:
```
"Write Gherkin scenarios for the Tasks feature at specs/features/tasks.feature.
Cover: create task (happy), list tasks (filtered by status), get task (happy + not found),
update task, delete task, unauthenticated request on all endpoints.
Status: draft."
```

Result: `specs/features/tasks.feature` (status: draft → reviewed → approved)

---

## Phase 2 — Architecture

**ADR-001 — Tech Stack**

Decision: Fastify + TypeScript + PostgreSQL + Prisma + Vitest + Dredd

Rationale: Fastify has native JSON Schema validation (aligns with our spec-first approach). Dredd integrates directly with OpenAPI for conformance testing. Prisma generates types from our database schema.

---

## Phase 3 — Implementation (Slice 1: Create & Get Task)

**Step 1 — Generate types**
```bash
npm run spec:generate
# Generates: src/types/task.ts from specs/schemas/task.schema.json
```

**Step 2 — Write failing conformance test**
```typescript
// test/conformance/tasks.test.ts
// Fails because implementation doesn't exist yet

describe("POST /tasks", () => {
  it("creates a task and returns 201 with Location header", async () => {
    const response = await request(app)
      .post("/api/v1/tasks")
      .set("Authorization", `Bearer ${validToken}`)
      .send({ title: "My Task" });

    expect(response.status).toBe(201);
    expect(response.headers.location).toMatch(/\/api\/v1\/tasks\//);
    expect(response.body.id).toMatch(UUID_REGEX);
    expect(response.body.status).toBe("todo");
  });
});
```

**Step 3 — Implement (in order: migration → repository → service → controller)**

```typescript
// src/modules/tasks/task.repository.ts
// src/modules/tasks/task.service.ts
// src/modules/tasks/task.controller.ts
```

**Step 4 — Gate check**
```bash
npm run spec:lint       # ✅ 0 errors
npm run typecheck       # ✅ 0 errors
npm run test:conformance # ✅ 5/5 endpoints pass
npm run test:behavior    # ✅ 12/12 scenarios pass
npm run security:audit   # ✅ 0 high vulnerabilities
```

---

## Key SDD Decisions Made During This Example

1. **Spec gap found**: During implementation, the spec didn't define behavior when `dueDate` is in the past. → Stopped, wrote a new Gherkin scenario (past due date is allowed, just a warning), got it approved, then implemented.

2. **Breaking change avoided**: Initially wanted to add `priority` field. → Checked the spec — it was not in the approved schema. → Added it to the schema as an optional field (non-breaking), got approval, then implemented.

3. **Conformance failure**: The first implementation returned 200 on POST instead of 201. → Gate 3 caught it. Fixed the controller. Spec wins.

---

## Final Spec Index

```
specs/
├── mission.md                    ✅ validated
├── requirements.md               ✅ validated
├── api/
│   └── tasks.openapi.yaml        ✅ validated (v1.0.0)
├── schemas/
│   └── task.schema.json          ✅ validated (v1.0.0)
├── features/
│   └── tasks.feature             ✅ validated
├── decisions/
│   ├── ADR-000-project-context.md  ✅ accepted
│   └── ADR-001-tech-stack.md       ✅ accepted
└── slos/
    └── api.slo.yaml               ✅ validated
```
