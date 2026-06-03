# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changelog entries always reference the spec that drove the change.
Format: `[Description] (spec: [spec-id] [version])`

---

## [Unreleased]

<!-- Add changes here as they are merged to the main branch.
     Move this section to a versioned release before tagging. -->

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

---

## [1.0.0] — [YYYY-MM-DD]

> First production release. Establishes the baseline spec surface.

### Added
- `GET /[resources]` — List endpoint with pagination (spec: api-[domain]-001 v1.0.0)
- `POST /[resources]` — Create endpoint (spec: api-[domain]-001 v1.0.0)
- `GET /[resources]/{id}` — Get by ID endpoint (spec: api-[domain]-001 v1.0.0)
- `PATCH /[resources]/{id}` — Partial update endpoint (spec: api-[domain]-001 v1.0.0)
- `DELETE /[resources]/{id}` — Delete endpoint (spec: api-[domain]-001 v1.0.0)
- `[Entity]` JSON Schema with full field definitions (spec: schema-[entity]-001 v1.0.0)
- JWT Bearer authentication for all protected endpoints (spec: adr-auth-001)
- Rate limiting headers on all endpoints (spec: api-[domain]-001 v1.0.0)
- Structured error envelope: `{ error: { code, message, requestId } }` (spec: api-[domain]-001 v1.0.0)

[1.0.0]: https://github.com/[org]/[repo]/releases/tag/v1.0.0
