# Spec Conventions

Uniform conventions across all spec types ensure that specs are readable by humans, tools, and AI agents without ambiguity.

---

## File Naming

```
specs/
├── api/
│   └── [domain].openapi.yaml         # e.g., tasks.openapi.yaml, auth.openapi.yaml
├── schemas/
│   └── [entity].schema.json          # e.g., task.schema.json, user.schema.json
├── features/
│   └── [feature-name].feature        # e.g., task-creation.feature, auth.feature
├── decisions/
│   └── ADR-[NNN]-[kebab-title].md    # e.g., ADR-001-tech-stack.md
├── contracts/
│   └── [consumer]-[provider].pact.json
├── events/
│   └── [domain].asyncapi.yaml
└── slos/
    └── [service].slo.yaml
```

**Rules**:
- All filenames: lowercase, kebab-case
- No spaces in filenames
- Version is in the file content (frontmatter), not in the filename
- One domain / resource per file (don't merge unrelated schemas)

---

## ID Convention

Every spec has a unique, stable ID. IDs never change after creation.

```
Format: [type]-[domain]-[NNN]

Types:
  api       → OpenAPI spec
  schema    → JSON Schema
  feat      → Gherkin feature file
  adr       → Architecture Decision Record
  pact      → Pact consumer contract
  event     → AsyncAPI event spec
  slo       → Service Level Objective
  mission   → Mission statement
  req       → Requirements
  arch      → Architecture document
  plan      → Implementation plan
  brief     → Product brief

Examples:
  api-tasks-001         → First tasks API spec
  schema-user-003       → Third user schema
  feat-checkout-007     → Seventh checkout feature spec
  adr-auth-002          → Second auth ADR
```

---

## Frontmatter Convention

Every spec file begins with YAML frontmatter:

```yaml
---
id: [type]-[domain]-[NNN]
title: "[Human-readable title]"
type: [openapi | json-schema | gherkin | adr | pact | asyncapi | slo | mission | requirements | architecture | plan]
status: [draft | reviewed | approved | implemented | validated | deprecated]
version: [MAJOR.MINOR.PATCH]
authors:
  - name: "[Full Name]"
    email: "[email]"
created: "[YYYY-MM-DD]"
updated: "[YYYY-MM-DD]"
depends_on:
  - [spec-id]      # IDs of specs this spec depends on
supersedes: ~      # ID of spec this replaces, if any
---
```

**Required fields**: `id`, `title`, `type`, `status`, `version`, `authors`, `created`, `updated`

**Gherkin exception**: Gherkin files don't support YAML frontmatter — use comments instead:
```gherkin
# id: feat-tasks-001
# status: approved
# version: 1.0.0
```

---

## Versioning Convention

Specs follow semantic versioning (SemVer):

| Change Type | Version Bump | Example |
|---|---|---|
| Fix typo, clarify description | `patch` | 1.0.0 → 1.0.1 |
| Add optional field, new endpoint | `minor` | 1.0.0 → 1.1.0 |
| Remove field, rename field, change type | `major` | 1.0.0 → 2.0.0 |

**Breaking change rule**: Any change that requires existing consumers to update their code or data is a breaking change → MAJOR bump.

---

## OpenAPI Conventions

### URL Design
```
/api/v1/[resources]             ← plural resource names
/api/v1/[resources]/{id}        ← UUID path param
/api/v1/[resources]/{id}/[sub]  ← max 2 nesting levels
```

### Operation IDs
Must be unique, camelCase, and describe the action:
```
list[Resources]        → GET /resources
create[Resource]       → POST /resources
get[Resource]ById      → GET /resources/{id}
update[Resource]       → PATCH /resources/{id}
replace[Resource]      → PUT /resources/{id}
delete[Resource]       → DELETE /resources/{id}
```

### Status Codes
```
200 OK              → Successful GET, PATCH, PUT
201 Created         → Successful POST (with Location header)
204 No Content      → Successful DELETE
400 Bad Request     → Invalid request syntax or constraint violation
401 Unauthorized    → Missing or invalid authentication
403 Forbidden       → Authenticated but not authorized
404 Not Found       → Resource does not exist
409 Conflict        → Resource state conflict (duplicate, version mismatch)
422 Unprocessable   → Syntactically valid but semantically invalid (business rule)
429 Too Many Requests → Rate limit exceeded
500 Internal Error  → Server error (never expose internal details)
```

### Response Schema Rules
- All response schemas use `additionalProperties: false`
- List responses always include a `meta` object with pagination info
- All entities include `id`, `createdAt`, `updatedAt`
- Error responses always use the standard error envelope

---

## JSON Schema Conventions

### Type Definitions
```json
{
  "type": "string",
  "minLength": 1,       // always set for non-empty strings
  "maxLength": 100,     // always set an upper bound
  "description": "...", // always describe the field
  "examples": ["..."]   // always provide at least one example
}
```

### Required Fields
```json
{
  "required": ["id", "name", "status", "createdAt", "updatedAt"],
  "additionalProperties": false
}
```

**Rule**: Always list `required` explicitly. Never rely on `additionalProperties` alone to enforce required fields.

### Enum Values
```json
{
  "type": "string",
  "enum": ["active", "inactive", "archived"],
  "description": "Lifecycle status. 'active' is the default.",
  "default": "active"
}
```

**Rule**: Always document what each enum value means.

### Read-Only vs Write-Only
```json
{
  "id": {
    "type": "string",
    "format": "uuid",
    "readOnly": true,    // set by server, not accepted in create/update
    "description": "Server-generated identifier."
  }
}
```

---

## Gherkin Conventions

### Structure
```gherkin
Feature: [Feature name — matches feature ID]
  As a [actor]
  I want to [action]
  So that [business value]

  Background:
    Given [shared preconditions for all scenarios]

  Scenario: [Action — Expected outcome]
    Given [specific context]
    When [single action]
    Then [expected result]
    And [additional assertion]
```

### Naming Rules
- Scenario names: imperative action → expected outcome (e.g., "Creating a task with missing title returns 400")
- No "test" or "verify" in scenario names — describe behavior, not test intent
- No "should" — use present tense
- Cover: happy path, auth error, validation error, not found, business rule violation

### Data Tables
```gherkin
When I create a task with:
  | field       | value             |
  | title       | "My Task"         |
  | status      | "todo"            |
```

Use data tables for structured inputs. Don't embed complex JSON in scenario text.

---

## ADR Conventions

### Numbering
```
ADR-000 — Project context (always first, written during discovery)
ADR-001 — First architectural decision
ADR-NNN — Sequential, never reuse numbers
```

### Status Values
```
Proposed   → Under discussion
Accepted   → Decision made and binding
Deprecated → Still in effect but superseded
Superseded → Replaced by ADR-[NNN]
```

### Required Sections
1. Context — what the problem is
2. Decision Drivers — what factors matter
3. Options Considered — at least 2 options with pros/cons
4. Decision — what was decided and why
5. Consequences — positive and negative
6. Spec Impact — what specs must be updated

---

## SPEC-INDEX.md Convention

A machine-readable index at `specs/SPEC-INDEX.md`:

```markdown
# Spec Index

Last updated: [YYYY-MM-DD]

## Status Legend
📝 draft  🔍 reviewed  🔵 approved  🔨 implemented  ✅ validated  ⚠️ deprecated

## API Specs

| ID | Title | Version | Status | Updated |
|---|---|---|---|---|
| api-tasks-001 | Tasks API | 1.1.1 | ✅ validated | 2024-03-25 |

## Schema Specs

| ID | Title | Version | Status | Updated |
|---|---|---|---|---|
| schema-task-001 | Task Schema | 1.1.0 | ✅ validated | 2024-03-25 |
```

**Rule**: Update SPEC-INDEX.md in the same commit as any spec status change.
