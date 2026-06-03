# Installation Guide

This guide covers how to apply the Bootstrap IA SDD ruleset to a new or existing project.

---

## Requirements

- Git (any recent version)
- A code editor: Cursor, VS Code, or any editor with AI assistant support
- For Claude Code: Claude Code CLI installed (`npm install -g @anthropic-ai/claude-code`)

---

## Option A — Start a New Project (Greenfield)

```bash
# 1. Create your project directory
mkdir my-project && cd my-project
git init

# 2. Copy the SDD bootstrap into your project
git clone https://github.com/GaetanOff/bootstrap-ia-sdd .sdd-bootstrap
# OR: download as a ZIP and extract

# 3. Copy the rule files
cp -r .sdd-bootstrap/.cursor ./
cp .sdd-bootstrap/CLAUDE.md ./
cp .sdd-bootstrap/AGENTS.md ./

# 4. Copy the templates you need
mkdir -p specs
cp -r .sdd-bootstrap/templates/specs/* ./templates/specs/

# 5. Remove the bootstrap source
rm -rf .sdd-bootstrap

# 6. Initialize your spec directory
mkdir -p specs/api specs/schemas specs/features specs/decisions specs/slos

# 7. Create your first mission document
cp templates/specs/mission.md specs/mission.md
# Edit specs/mission.md to describe your project

# 8. Initialize SPEC-INDEX.md
echo "# Spec Index\n\n_No specs yet._" > specs/SPEC-INDEX.md

# 9. Initialize CHANGELOG.md
cp templates/specs/changelog.md CHANGELOG.md
```

---

## Option B — Add to an Existing Project

```bash
# 1. Clone the bootstrap temporarily
git clone https://github.com/GaetanOff/bootstrap-ia-sdd /tmp/sdd-bootstrap

# 2. Add Cursor rules (check if .cursor/rules/ already exists)
mkdir -p .cursor/rules
cp /tmp/sdd-bootstrap/.cursor/rules/*.mdc .cursor/rules/

# 3. Add or update CLAUDE.md
# If CLAUDE.md already exists: append the SDD content
cat /tmp/sdd-bootstrap/CLAUDE.md >> CLAUDE.md
# If it doesn't exist: copy it directly
cp /tmp/sdd-bootstrap/CLAUDE.md ./

# 4. Copy workflow templates
mkdir -p templates
cp -r /tmp/sdd-bootstrap/templates ./

# 5. Create specs/ directory if missing
mkdir -p specs/api specs/schemas specs/features specs/decisions

# 6. Run the legacy workflow
# See: templates/workflows/legacy.md
# First step: audit existing spec coverage

# 7. Clean up
rm -rf /tmp/sdd-bootstrap
```

---

## Option C — Use as a Git Submodule

```bash
# Add as submodule (tracks updates to the ruleset)
git submodule add https://github.com/GaetanOff/bootstrap-ia-sdd .sdd

# Create symlinks so tools find the rules
ln -s .sdd/.cursor/rules .cursor/rules
ln -s .sdd/CLAUDE.md CLAUDE.md
ln -s .sdd/AGENTS.md AGENTS.md

# Update the ruleset when needed
git submodule update --remote
```

---

## Configuring Your Editor

### Cursor

Rules are automatically picked up from `.cursor/rules/*.mdc`. No configuration needed.

To verify:
1. Open Cursor in your project directory
2. Open Composer (Cmd/Ctrl + I)
3. Type "What SDD phase am I in?" — Cursor should apply the rules automatically

### Claude Code

```bash
# If using project-level CLAUDE.md (recommended):
# The file at <project-root>/CLAUDE.md is automatically loaded

# To verify:
claude "What SDD rules apply to this project?"
```

### VS Code with GitHub Copilot

```bash
# Create a .github/copilot-instructions.md file
# (Copilot reads this as system instructions)
cp CLAUDE.md .github/copilot-instructions.md
```

### Generic Agents (OpenCode, etc.)

```bash
# AGENTS.md is the entrypoint for agents that read this convention
# Place it at the project root — agents following the AGENTS.md convention
# will pick it up automatically
```

---

## Setting Up Conformance Tooling

### For Node.js / TypeScript Projects

```bash
npm install --save-dev @stoplight/spectral-cli
npm install --save-dev dredd
npm install --save-dev @openapitools/openapi-generator-cli
npm install --save-dev json-schema-to-typescript

# Add to package.json scripts:
{
  "scripts": {
    "spec:lint": "spectral lint specs/api/*.openapi.yaml",
    "spec:generate": "openapi-generator-cli generate -i specs/api/[domain].openapi.yaml -g typescript-fetch -o src/generated",
    "spec:types": "json2ts -i specs/schemas/*.json -o src/types/",
    "spec:test": "dredd specs/api/[domain].openapi.yaml http://localhost:3000",
    "typecheck": "tsc --noEmit",
    "test:conformance": "vitest run test/conformance/",
    "test:behavior": "cucumber-js specs/features/"
  }
}
```

### For Python Projects

```bash
pip install openapi-spec-validator spectral-py
pip install dredd-hooks  # for Dredd with Python

# Or use schemathesis:
pip install schemathesis

# Run:
schemathesis run specs/api/[domain].openapi.yaml --base-url http://localhost:8000
```

### For Go Projects

```bash
go install github.com/loopfuse/godantic@latest  # JSON Schema validation
# Use go-swagger or oapi-codegen for code generation from OpenAPI
go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest
```

---

## Spectral Configuration

Create `.spectral.yaml` at project root:

```yaml
extends:
  - spectral:oas
  - "@stoplight/spectral-owasp-ruleset"

rules:
  operation-description: warn
  operation-operationId: error
  info-contact: warn
  openapi-tags: warn

  # Custom rule: all responses must use the error envelope
  error-envelope:
    description: "4xx and 5xx responses must use the standard error envelope"
    message: "{{error}} — use the ErrorResponse component"
    given: "$.paths[*][*].responses[?(@property >= '400')].content.application/json.schema"
    then:
      field: "$ref"
      function: pattern
      functionOptions:
        match: ".*ErrorResponse.*"
    severity: error
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/spec-gates.yml
name: Spec Gates

on: [push, pull_request]

jobs:
  spec-gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: npm ci

      - name: Gate 1 — Spec Lint
        run: npm run spec:lint

      - name: Gate 2 — Type Check
        run: npm run spec:generate && npm run typecheck

      - name: Gate 3 — Start server
        run: npm run start:test &
        env:
          NODE_ENV: test
          DATABASE_URL: ${{ secrets.TEST_DATABASE_URL }}

      - name: Gate 3 — Conformance Tests
        run: npm run test:conformance

      - name: Gate 4 — Behavior Tests
        run: npm run test:behavior

      - name: Gate 5 — Security Audit
        run: npm run security:audit
```

---

## Verifying the Setup

```bash
# Check all rules are loaded
ls .cursor/rules/core-*.mdc    # Should show 18 core rules
ls .cursor/rules/global-*.mdc  # Should show 10 global rules

# Check templates are available
ls templates/specs/            # Should show 10+ templates

# Check CLAUDE.md is present
head -5 CLAUDE.md              # Should show SDD instructions

# Run spec lint on the template (should produce no errors)
npm run spec:lint -- templates/specs/api.openapi.yaml
```
