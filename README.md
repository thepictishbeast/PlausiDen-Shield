# PlausiDen Shield

If you run your own servers, you know the problem: commercial admin dashboards want you to install their agent, send your telemetry to their cloud, and trust that their access controls are sufficient. For anyone managing infrastructure that handles sensitive data -- voting records, legal communications, health data -- that trust model is backwards. Your server administration tool should not be a surveillance vector.

## The Problem

Self-hosted server operators need a way to monitor systems, manage services, track issues, and control access without depending on third-party SaaS dashboards that introduce supply-chain risk and data exfiltration surface. Defense attorneys, journalists, and civic organizations running their own infrastructure need admin tools they can audit, deploy as a single binary, and lock down with access controls that go beyond simple role checks.

## How It Works

Shield is a single Rust binary (Axum + SQLite) that serves a REST API and web frontend for Linux server administration. Every operation -- service management, file operations, firewall rules, system monitoring -- goes through a safe command executor that prevents shell injection by design. No commands are assembled from string concatenation; every system interaction is a typed, validated operation.

```
Request
  |
  v
Six-Layer Access Control
  1. RBAC    -- Role-Based Access Control (admin, operator, viewer)
  2. ABAC    -- Attribute-Based Access Control (time, IP, resource properties)
  3. PBAC    -- Policy-Based Access Control (NeuPSL probabilistic rules)
  4. MAC     -- Mandatory Access Control (classification labels)
  5. SoD     -- Separation of Duties (no single user can approve their own action)
  6. Context -- Contextual evaluation (threat level, system state)
  |
  v
Safe Executor (typed commands, no shell)
  |
  v
System / Database / Integration Bus
```

**Key design decisions:**

- **Single binary deployment.** One `plausiden-shield` binary, one SQLite database, one TOML config file. No container orchestration, no microservices, no external database server.
- **Six-layer access control.** Most admin tools offer RBAC at best. Shield layers six independent access control mechanisms, including NeuPSL probabilistic policy evaluation for nuanced, context-aware authorization.
- **Safe command execution.** The executor module accepts typed command structs, not shell strings. There is no `sh -c` anywhere in the codebase. Command arguments are validated and escaped at the type level.
- **Argon2 + TOTP authentication.** Password hashing uses Argon2id. Two-factor authentication via TOTP is built in, not bolted on.

### Modules

| Module | Purpose |
|--------|---------|
| `auth/` | RBAC, ABAC, MAC, SoD, session management, policy engine |
| `executor/` | Safe command execution layer |
| `monitor/` | System resource monitoring via sysinfo |
| `api/` | REST endpoints: system, services, firewall, files, antivirus, IDS |
| `tickets/` | Issue and change tracking |
| `analytics/` | Operational analytics and reporting |
| `integrations/` | External system integration bus |

## Current Status

| Component | Status |
|-----------|--------|
| REST API + web frontend | Working |
| Six-layer access control | Working |
| Safe command executor | Working |
| System monitoring | Working |
| Ticket tracking | Working |
| Argon2 + JWT + TOTP auth | Working |
| NeuPSL policy engine | Working |
| Integration bus | Scaffolded |

## Quick Start

```bash
git clone https://github.com/thepictishbeast/PlausiDen-Shield.git
cd PlausiDen-Shield
cargo build --release

# Copy the example config
sudo mkdir -p /etc/plausiden-shield
sudo cp shield.toml.example /etc/plausiden-shield/shield.toml
# Edit the config for your environment

# Run
./target/release/plausiden-shield --config /etc/plausiden-shield/shield.toml --port 8443
```

Or for development:

```bash
cargo run -- --config shield.toml --port 3000
```

## The PlausiDen Ecosystem

Shield is the operations platform for all PlausiDen infrastructure. It manages the servers that run Sacred.Vote, the mail orchestrator, and the plausible deniability engine. Its NeuPSL-based policy engine uses the Neurosymbolic Toolkit for access control decisions that go beyond static rules. Shield is designed to be domain-agnostic -- it administers any Linux server, not just PlausiDen servers.

## License

BSL 1.1 (Business Source License) with a 4-year change date to Apache 2.0.

You can use Shield for any non-production purpose immediately. Production use requires a commercial license until the change date, after which the code becomes Apache 2.0.
