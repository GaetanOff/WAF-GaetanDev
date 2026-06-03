# SDD Philosophy — Spec Driven Development

---

## The Core Idea

Code is ephemeral. Contracts are permanent.

In traditional development, the code is the source of truth. If you want to know how an API works, you read the code. If you want to know what a data model contains, you look at the database. The documentation, if it exists, is a lagging, approximate summary of what the code does today.

In Spec Driven Development, the spec is the source of truth. The code is an implementation of the spec. If the code and the spec disagree, the spec wins. The code is changed to match the spec, not the other way around.

This inversion has profound consequences.

---

## Why Specs First?

### Contracts survive refactors

When you refactor the implementation of an API endpoint, the contract (what it accepts, what it returns, what errors it produces) can stay exactly the same. Consumers of the API notice nothing. The spec didn't change — only the code did.

Without a spec, you don't know what the contract was. Every refactor risks breaking something invisible.

### Specs are the cheapest form of documentation

An OpenAPI spec is machine-readable documentation. It generates:
- TypeScript types (zero manual effort)
- API client code (zero manual effort)
- API reference documentation (zero manual effort)
- Conformance tests (zero manual effort)
- Mock servers for frontend development (zero manual effort)

One spec file. Five artifacts. All always in sync.

### Specs force clarity before commitment

Writing a spec for a feature forces you to answer questions that code never forces you to answer:
- What does the response look like when the input is invalid?
- What error code does a 404 return?
- Is this field required or optional?
- What is the maximum length of this string?

When writing code, developers resolve these questions implicitly and inconsistently. When writing a spec, they resolve them explicitly and permanently.

### Specs make AI agents predictable

AI coding agents (Cursor, Claude Code, GitHub Copilot) are eager to implement. Given a vague requirement, they will fill in the gaps with plausible-but-wrong assumptions. Specs eliminate the guessing.

When you tell an agent "implement this endpoint" and hand it an approved OpenAPI spec, it generates code that matches the contract. When you tell it "implement this feature", it generates code that matches whatever it imagines the feature should do.

SDD turns AI agents from creative writers into precise implementers.

---

## The SDD Invariants

These are non-negotiable. They define what SDD is.

1. **Specs precede code.** A spec must be at `status: approved` before any implementation begins.
2. **Specs are the contract.** When code and spec disagree, the spec wins.
3. **Specs are machine-readable.** OpenAPI, JSON Schema, Gherkin — not prose, not Notion docs.
4. **Specs are versioned.** They have semantic versions and a defined lifecycle (draft → approved → validated → deprecated).
5. **Conformance is automated.** Gates run in CI. Humans do not manually verify conformance.
6. **Discovery precedes specs.** Vague requirements generate vague specs. Specs are written after questions are answered.

---

## What SDD Is Not

**SDD is not Big Spec Upfront (BSUF).**

Traditional waterfall projects wrote massive specification documents before any code. These specs were prose, not machine-readable. They grew stale immediately. By the time implementation started, they were outdated.

SDD specs are:
- Machine-readable (they generate code and tests)
- Minimal (one spec per feature or domain, not hundreds of pages)
- Evolutionary (they change as requirements change — and the code follows)
- Automated (conformance is tested, not read)

The goal is not to specify everything before coding everything. The goal is to specify each feature before implementing that feature.

---

## What SDD Is Not (Part 2)

**SDD is not a bureaucratic process.**

A spec review is not a committee meeting. For a one-person project, it's a self-review. For a team, it's a PR review of the spec file, not a multi-stakeholder approval process.

The goal of the review is: "Is this spec clear, complete, and consistent with the existing contracts?" If yes — approve and implement.

---

## The Anti-Vibe Coding Principle

"Vibe coding" is the practice of writing code that feels right based on intuition, without any formal specification. It produces working prototypes quickly and unmaintainable production systems.

The signs of vibe coding:
- You start implementing before you've defined what "done" looks like
- You resolve ambiguity with your best guess instead of asking
- You write code to explore the problem instead of specs
- The "specification" is a Slack message or a rough verbal description
- You find the edge cases during code review, not during spec review

SDD replaces vibe coding with a simple rule: **if you can't write a Gherkin scenario for it, you don't understand it well enough to code it.**

This is not a productivity obstacle. It is a productivity multiplier. The hour spent writing a Gherkin scenario eliminates the three hours spent debugging unexpected behavior in production.

---

## When to Break the Rules

SDD rules are designed for production software. They apply to:
- Features that will be maintained for more than a month
- APIs with external consumers
- Data models that will be migrated or evolved
- Systems where correctness matters

They do not apply to:
- Throwaway prototypes (explicitly time-boxed explorations, discarded after)
- One-off scripts
- Pure UI/design explorations

For a prototype that will be discarded, write no specs. For a prototype that might become production code, write specs the moment you decide to keep it.
