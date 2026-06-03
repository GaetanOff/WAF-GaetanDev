# Using Bootstrap IA SDD with Cursor

---

## Setup

```bash
# Copy the rules directory to your project
cp -r /path/to/bootstrap-ia-sdd/.cursor ./

# Verify the rules are in place
ls .cursor/rules/core-*.mdc
```

Cursor automatically loads all `.mdc` files from `.cursor/rules/` when you open the project. No configuration required.

---

## How Rules Are Applied

**`alwaysApply: true` rules** (core-* and global-*): Active in all conversations, regardless of which files are open.

**`alwaysApply: false` rules** (specific-*): Activated automatically when you open a file matching the glob pattern (e.g., `specific-typescript.mdc` activates when you open a `.ts` file).

---

## Recommended Workflow in Cursor

### 1. Use Composer (not Chat) for SDD work

Composer maintains context across a longer sequence of prompts. This is essential for multi-step SDD workflows.

Open Composer: `Cmd/Ctrl + I`

### 2. Reference specs with @

```
@specs/api/tasks.openapi.yaml
@specs/schemas/task.schema.json
@specs/features/tasks.feature
```

This ensures Claude uses the spec as the authoritative contract, not inferred behavior from the code.

### 3. Start Discovery

```
In Composer:

"I want to implement [feature].
Before writing any spec, run the SDD discovery protocol.
Ask me the 5 minimum questions: WHO, WHAT, WHEN, WHY WRONG, DONE."
```

### 4. Step-by-Step Prompting

Do not combine phases into one prompt. Use a separate prompt per step:

```
Step 1: "Write the data schema for [entity] at specs/schemas/[entity].schema.json"
[Wait for output — review — provide feedback]

Step 2: "Write the OpenAPI spec for [domain] at specs/api/[domain].openapi.yaml"
[Wait for output — review — approve]

Step 3: "Scaffold conformance tests from @specs/api/[domain].openapi.yaml"
[Wait for output — run tests — confirm they fail]

Step 4: "Implement [feature] against the approved spec at @specs/..."
[Wait for output — run gate checks]
```

### 5. Use the Notepad for Status Tracking

In Cursor's Notepad (if available), maintain a spec status tracker:
```
# SDD Status — [Feature Name]

Spec phase:
- [x] JSON Schema — specs/schemas/task.schema.json (approved)
- [x] OpenAPI — specs/api/tasks.openapi.yaml (approved)
- [ ] Gherkin — specs/features/tasks.feature (pending review)

Implementation phase:
- [x] Types generated
- [x] Migration written
- [ ] Conformance tests (failing — in progress)
- [ ] Repository layer
- [ ] Service layer
- [ ] Controller layer
```

---

## Cursor-Specific Tips

### Force spec-first behavior

If Cursor tries to write implementation code before specs:
```
"Stop. We are still in the Specification phase.
Write the spec for [X] at specs/[path].
Do not write any implementation code yet."
```

### Reference multiple files at once

```
"Check @src/modules/tasks/ against @specs/api/tasks.openapi.yaml.
List every gap: routes with no spec, response fields not in schema."
```

### Use Cmd+L to add context

Add files to the conversation context with `@` or by pressing `Cmd+L` and selecting files. Always add the relevant spec files before asking for implementation.

---

## Rule Priority

If you have a custom `.cursor/rules/` directory, the Bootstrap IA rules coexist with your existing rules. To ensure SDD rules take priority, rename them with a low prefix (e.g., `00-core-workflow.mdc`). Cursor applies rules in alphabetical order within the same `alwaysApply` group.

---

## Verifying Rules Are Active

In Cursor Composer:
```
"What SDD rules apply to this project?
List the core SDD phases and the current phase we should be in."
```

If the rules are loaded correctly, Cursor will describe the SDD workflow phases and ask which phase you're in.
