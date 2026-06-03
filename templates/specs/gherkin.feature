# Feature file template — Spec Driven Development
# File: specs/features/[feature-name].feature
#
# Metadata (YAML frontmatter in comments — parseable by tooling)
# id: feat-[domain]-[NNN]
# title: [Feature Name]
# status: draft
# version: 1.0.0
# authors: [Author Name]
# created: [YYYY-MM-DD]
# depends_on: api-[domain]-[NNN], schema-[entity]-[NNN]

Feature: [Feature Name]
  As a [actor/role]
  I want to [action or capability]
  So that [business value or outcome]

  Background:
    Given the system is operational
    And the database is clean
    And a user account exists with email "user@example.com" and password "Test1234!"

  # ─────────────────────────────────────────────────────────────
  # Happy Path — the expected successful flow
  # ─────────────────────────────────────────────────────────────

  Scenario: Successful [main action]
    Given I am authenticated as "user@example.com"
    And [any precondition]
    When I [perform the main action] with:
      | field       | value              |
      | name        | "My Resource"      |
      | description | "A test resource"  |
    Then the response status is 201
    And the response body contains a resource with:
      | field       | value             |
      | name        | "My Resource"     |
      | status      | "active"          |
    And the response body contains a valid UUID for "id"
    And the response body contains a valid ISO 8601 datetime for "createdAt"
    And the Location header points to the new resource

  Scenario: [Second happy path variant — e.g., with optional fields]
    Given I am authenticated as "user@example.com"
    When I [perform the action] with only required fields:
      | field | value        |
      | name  | "Minimal"    |
    Then the response status is 201
    And the resource is created with defaults applied:
      | field  | default value |
      | status | "active"      |

  # ─────────────────────────────────────────────────────────────
  # Error Paths — every 4xx case must have a scenario
  # ─────────────────────────────────────────────────────────────

  Scenario: Unauthenticated request is rejected
    Given I am not authenticated
    When I [perform the action]
    Then the response status is 401
    And the error code is "UNAUTHORIZED"
    And the response body contains a "requestId"

  Scenario: Missing required field returns validation error
    Given I am authenticated as "user@example.com"
    When I [perform the action] without the "name" field
    Then the response status is 400
    And the error code is "VALIDATION_ERROR"
    And the error details contain a message for "name"

  Scenario: Field exceeds maximum length
    Given I am authenticated as "user@example.com"
    When I [perform the action] with "name" set to a 101-character string
    Then the response status is 400
    And the error code is "VALIDATION_ERROR"
    And the error details contain a message for "name"

  Scenario: Accessing another user's resource is forbidden
    Given I am authenticated as "other@example.com"
    And a resource owned by "user@example.com" with id "resource-id-001" exists
    When I request the resource with id "resource-id-001"
    Then the response status is 403
    And the error code is "FORBIDDEN"

  Scenario: Requesting a non-existent resource returns 404
    Given I am authenticated as "user@example.com"
    When I request the resource with id "non-existent-id"
    Then the response status is 404
    And the error code is "RESOURCE_NOT_FOUND"

  # ─────────────────────────────────────────────────────────────
  # Edge Cases
  # ─────────────────────────────────────────────────────────────

  Scenario: Request with additional unknown fields is rejected
    Given I am authenticated as "user@example.com"
    When I [perform the action] with an extra field "unknownField": "value"
    Then the response status is 400
    And the error code is "VALIDATION_ERROR"

  Scenario: Concurrent creation of resources with the same name
    Given I am authenticated as "user@example.com"
    When I send two concurrent POST requests with name "Duplicate"
    Then both requests complete without server error
    And two distinct resources exist with name "Duplicate"

  # ─────────────────────────────────────────────────────────────
  # @wip — scenarios not yet implemented (block release)
  # Remove @wip tag when implementation is complete
  # ─────────────────────────────────────────────────────────────

  @wip
  Scenario: [Scenario not yet implemented]
    Given [precondition]
    When [action]
    Then [expected outcome]
