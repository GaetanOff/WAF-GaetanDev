# Using Bootstrap IA SDD with Claude Code

---

## Setup

```bash
# Copy CLAUDE.md to your project root
cp /path/to/bootstrap-ia-sdd/CLAUDE.md ./CLAUDE.md

# Optionally add the Cursor rules for cross-tool compatibility
cp -r /path/to/bootstrap-ia-sdd/.cursor/rules .cursor/rules
```

Claude Code automatically loads `CLAUDE.md` at project root. No further configuration needed.

---

## How the Rules Are Applied

When you open a conversation in Claude Code in this project:
1. Claude reads `CLAUDE.md` at startup
2. All SDD rules are active for the entire session
3. Claude will refuse to write implementation code without a spec
4. Claude will ask discovery questions if the request is vague

---

## Recommended Prompting Patterns

### Starting a Feature

```bash
# In your terminal, start Claude Code
claude

# Then in the conversation:
> "I want to add user authentication.
  Follow the SDD discovery protocol first.
  Ask me the 5 questions before writing any spec."
```

Claude will ask: WHO, WHAT, WHEN, WHY WRONG, DONE — then write specs, wait for your approval, then implement.

### Reviewing a Spec

```bash
# Reference the spec file directly
> "Review the spec at specs/api/auth.openapi.yaml.
  Check it against specs/requirements.md.
  Tell me what's missing before I approve it."
```

### Implementing a Slice

```bash
# After specs are approved
> "Implement the createUser operation from specs/api/auth.openapi.yaml.
  Follow SDD implementation order:
  types → migration → failing test → repository → service → controller."
```

### Running Gate Checks

```bash
> "Run the full gate check for the auth feature.
  Report each gate: spec:lint, typecheck, test:conformance, test:behavior, security:audit."
```

---

## Using @ References

Claude Code supports file references in prompts:

```bash
# Reference specific files
> "Write conformance tests for @specs/api/tasks.openapi.yaml"

# Reference directories
> "Analyze all specs in @specs/ for consistency issues"

# Reference multiple files
> "Check @src/modules/tasks/ against @specs/api/tasks.openapi.yaml"
```

---

## Session Handoff

For long-running SDD work, start new sessions with the handoff prompt:

```bash
claude

> "Handoff context:
  Project: TaskManager API
  Phase: Spec-First Implementation — Slice 2 (Task Labels)
  Last completed: Conformance tests written and failing correctly
  Next action: Implement the repository layer for labels

  Active specs:
  - @specs/api/tasks.openapi.yaml (v1.1.0, status: approved)
  - @specs/schemas/task.schema.json (v1.1.0, status: approved)
  - @specs/features/tasks.feature (v1.1.0, status: approved)"
```

---

## CLAUDE.md Structure

The `CLAUDE.md` in this project is structured as an orchestration entrypoint:

1. **Quick Start** — which workflow to use based on your project mode
2. **Phase Reference** — a compact reference to each SDD phase
3. **Active Rules Summary** — what rules are in force
4. **Critical Invariants** — the non-negotiable rules Claude will enforce
5. **Prompt Library** — ready-to-use prompts for common SDD scenarios

---

## Tips

- **Be explicit about the phase**: "We're in Phase 1 — Specification" prevents Claude from jumping ahead.
- **Approve specs explicitly**: "The spec is approved, set status: approved" — don't leave spec status implicit.
- **Use the gate check prompt**: "Run the full gate check and report each gate" — Claude will run each check in sequence and report failures.
- **Interrupt spec drift**: If Claude modifies a spec without explanation, ask "Is this a breaking change? Does it need a version bump?"
