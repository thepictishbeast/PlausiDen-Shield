# Architecture

## Overview

PlausiDen Shield is a single-binary Linux server administration platform (Axum + SQLite) with six-layer access control, safe command execution, and NeuPSL probabilistic policy evaluation. It replaces third-party SaaS dashboards with a self-hosted, auditable tool that introduces no supply-chain risk.

## System Diagram

```
                         HTTPS / WebSocket
                               |
                     +---------v----------+
                     |    Axum Router      |
                     |  (REST + static)    |
                     +---------+----------+
                               |
              +----------------v-----------------+
              |     Six-Layer Access Control      |
              |                                   |
              |  1. RBAC   (role gates)           |
              |  2. ABAC   (time, IP, resource)   |
              |  3. PBAC   (NeuPSL rules)         |
              |  4. MAC    (classification labels) |
              |  5. SoD    (duty separation)       |
              |  6. Context (threat level, state)  |
              +----------------+-----------------+
                               |
         +----------+----------+----------+-----------+
         |          |          |          |           |
     api/       monitor/   tickets/  analytics/  integrations/
  (endpoints)  (sysinfo)  (issues)  (reports)    (ext bus)
         |          |          |          |           |
         +----------+----+-----+----------+-----------+
                         |
              +----------v----------+
              |   Safe Executor     |
              | (typed cmds, no sh) |
              +----------+----------+
                         |
              +----------v----------+
              |  SQLite  |  System  |
              +---------------------+
```

## Data Flow

1. Client sends an authenticated request (JWT + optional TOTP).
2. Auth middleware validates the token and extracts session/role claims.
3. The request passes through all six access-control layers sequentially; any layer can deny.
4. PBAC evaluates NeuPSL weighted rules for context-sensitive decisions.
5. Permitted requests reach the API handler, which constructs a typed command struct.
6. The safe executor validates the struct and invokes the system call directly (no shell).
7. Results are persisted to SQLite and/or returned to the client as JSON.

## Key Design Decisions

- **Single binary, zero microservices.** One binary, one SQLite file, one TOML config. Minimizes attack surface and deployment complexity.
- **No shell invocation anywhere.** Every system interaction is a typed, validated struct. Eliminates shell injection by construction.
- **Six independent access layers.** Layers compose; each evaluates independently. RBAC alone would miss time-of-day restrictions; ABAC alone would miss duty-separation requirements.
- **NeuPSL for policy (PBAC).** Probabilistic soft logic enables graduated, context-aware access decisions that static rules cannot express.
- **Argon2id + TOTP authentication.** Password hashing and 2FA are built into the binary, not delegated to an external IdP.

## Threat Model

**Defends against:** shell injection, privilege escalation via role confusion, unauthorized access from stolen JWTs (TOTP required), single-operator abuse (SoD layer), data exfiltration through admin tooling (no cloud telemetry).

**Out of scope:** kernel exploits, physical access to the server, compromise of the SQLite database file at rest (encrypt-at-rest is planned), DDoS at the network level.

## Future Directions

- Encrypt SQLite database at rest with SQLCipher or similar.
- Phoenix LiveView dashboard (Elixir) for real-time monitoring alongside the REST API.
- Webhook-based integration bus for alerting to external systems.
- Formal verification of access-control layer composition in Lean 4.
- OpenTelemetry export for observability without cloud dependency.
