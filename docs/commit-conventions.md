# Commit Conventions

All commits follow the [Conventional Commits](https://www.conventionalcommits.org/) specification, extended with SDD-specific types.

---

## Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Rules**:
- Type and scope in lowercase
- Description in imperative mood, present tense ("add" not "added", "fix" not "fixed")
- No period at end of description
- Max 72 characters in the subject line
- Body and footer separated from subject by a blank line

---

## Types

| Type | Use When |
|---|---|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `spec` | New or updated spec file (no code change) |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests (conformance, unit, integration) |
| `chore` | Build process, dependency updates, tooling |
| `docs` | Documentation changes (README, docs/) |
| `perf` | Performance improvement |
| `ci` | CI/CD configuration changes |
| `revert` | Revert a previous commit |
| `adr` | New Architecture Decision Record |

**SDD-specific type**: `spec` is for spec file changes only. Code changes that implement a spec use `feat` or `fix`.

---

## Scope

The scope identifies the domain or module affected:

```
feat(tasks): add label filtering to list endpoint
spec(tasks): approve task labels delta spec
fix(auth): return 401 instead of 403 for missing token
adr(auth): accept JWT strategy decision
```

Common scopes:
- `[domain]` — business domain (tasks, users, orders, auth, payments)
- `[service]` — service name in a multi-service architecture
- `deps` — dependency updates
- `ci` — CI/CD pipeline
- `config` — configuration files
- `types` — generated type files

---

## Breaking Changes

Mark breaking changes in the footer with `BREAKING CHANGE:`:

```
feat(users)!: rename fullName field to firstName + lastName

The user entity no longer has a fullName field.
Clients must use firstName and lastName separately.

BREAKING CHANGE: user.fullName removed. Use user.firstName + user.lastName.
Spec: schema-user-001 v2.0.0
Migration guide: docs/migration/v2.0.0.md
```

The `!` after the type/scope also marks it as breaking.

---

## SDD-Specific Commit Examples

```bash
# Spec lifecycle transitions
spec(tasks): draft task labels schema and OpenAPI delta
spec(tasks): approve task labels specs after review
spec(tasks): promote task labels specs to validated

# Implementation following spec
feat(tasks): implement label field per schema-task-001 v1.1.0
test(tasks): add conformance tests for label filtering
fix(tasks): return 422 PAST_DUE_DATE for historical dates per spec

# ADR commits
adr(auth): accept JWT Bearer strategy — ADR-002
adr(db): accept PostgreSQL + Prisma for persistence — ADR-003

# Release
chore(release): v1.1.0
```

---

## Commit Body with Spec References

For non-trivial changes, include the spec reference in the body:

```
feat(tasks): add due date validation

Tasks with a due date in the past are now rejected with 422 PAST_DUE_DATE.

Spec: api-tasks-001 v1.1.1 (POST /tasks, 422 response)
Closes JIRA-1234
```

---

## Branch Naming

```
feat/<ticket>-<kebab-description>     → feature work
fix/<ticket>-<kebab-description>      → bug fixes
spec/<ticket>-<kebab-description>     → spec-only changes
refactor/<ticket>-<kebab-description> → refactoring
release/v<X>.<Y>.<Z>                  → release preparation
```

Examples:
```
feat/TASK-42-task-labels
fix/TASK-99-past-due-date-validation
spec/TASK-42-task-labels-schema
release/v1.1.0
```

---

## What Not to Commit

- `.env` files (use `.env.example` instead)
- Generated files (types, client code) — generate in CI
- `node_modules`, `__pycache__`, build artifacts
- Spec files with `status: draft` in a release branch (only approved or higher)
- Hardcoded credentials or API keys

---

## Commit Frequency

- Commit after each spec file reaches a new lifecycle state (draft, approved, implemented, validated)
- Commit after each vertical slice is complete and gates pass
- Never commit broken state (failing tests, linting errors)
- Small, focused commits — one logical change per commit
