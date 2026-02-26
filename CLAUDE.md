# CLAUDE.md — AumOS Government/Defense Overlay

## Project Overview

AumOS Enterprise is a composable enterprise AI platform with 9 products + 2 services
across 62 repositories. This repo (`aumos-govdef-overlay`) is part of **Tier B: Open Core**:
Vertical compliance overlays for regulated industries.

**Release Tier:** B: Open Core
**Product Mapping:** Product 7 — Compliance & Governance Overlays
**Phase:** 3 (Months 9-14)

## Repo Purpose

Provides Government/Defense compliance automation for enterprises operating in regulated
federal environments. Covers FedRAMP authorization lifecycle management, NIST SP 800-53
control mapping and evidence tracking, CMMC Level 3 assessment and gap analysis, sovereign
cloud deployment configuration for AWS GovCloud/Azure Government/GCC High, and IL4/IL5
air-gapped classified environment management.

## Architecture Position

```
aumos-platform-core → aumos-auth-gateway → aumos-govdef-overlay
                                          ↘ aumos-event-bus (compliance + deployment events)
                                          ↘ aumos-data-layer (gdf_ tables)
                                          ↘ aumos-governance-engine (policy enforcement)
```

**Upstream dependencies (this repo IMPORTS from):**
- `aumos-common` — auth, database, events, errors, config, health, pagination
- `aumos-proto` — Protobuf message definitions for Kafka events

**Downstream dependents (other repos IMPORT from this):**
- `aumos-governance-engine` — uses FedRAMP/NIST status for policy decisions
- `aumos-security-runtime` — uses IL level data for runtime security controls
- `aumos-observability` — subscribes to compliance events for dashboards

## Tech Stack (DO NOT DEVIATE)

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.110+ | REST API framework |
| SQLAlchemy | 2.0+ (async) | Database ORM |
| asyncpg | 0.29+ | PostgreSQL async driver |
| Pydantic | 2.6+ | Data validation, settings, API schemas |
| confluent-kafka | 2.3+ | Kafka producer/consumer |
| structlog | 24.1+ | Structured JSON logging |
| OpenTelemetry | 1.23+ | Distributed tracing |
| pytest | 8.0+ | Testing framework |
| ruff | 0.3+ | Linting and formatting |
| mypy | 1.8+ | Type checking |

## Domain Terminology

- **FedRAMP**: Federal Risk and Authorization Management Program — US federal cloud authorization
- **ATO**: Authority to Operate — final FedRAMP authorization grant
- **NIST 800-53**: NIST Special Publication 800-53, Security and Privacy Controls for IS
- **CMMC**: Cybersecurity Maturity Model Certification — DoD contractor requirement
- **C3PAO**: Certified Third-Party Assessment Organization (CMMC assessor)
- **CUI**: Controlled Unclassified Information
- **IL4/IL5**: DoD Impact Levels 4 and 5 (sensitive/national security data)
- **GCC High**: Microsoft Government Community Cloud High for DoD contractors
- **SPRS**: Supplier Performance Risk System — DoD contractor scoring database
- **POAM**: Plan of Action and Milestones — remediation tracking document

## Database

Table prefix: `gdf_`

| Table | Purpose |
|-------|---------|
| `gdf_fedramp_assessments` | FedRAMP readiness and authorization records |
| `gdf_nist_controls` | NIST 800-53 control mapping status per tenant |
| `gdf_cmmc_assessments` | CMMC level assessments and practice scoring |
| `gdf_sovereign_deployments` | Sovereign cloud deployment configurations |
| `gdf_classified_environments` | Air-gapped IL4/IL5 environment configs |

## API Routes

All routes are under `/api/v1/govdef/`:

| Method | Path | Service |
|--------|------|---------|
| POST | `/fedramp/assess` | FedRAMPService.assess_readiness |
| GET | `/fedramp/status?agency_id=` | FedRAMPService.get_authorization_status |
| POST | `/nist/map` | NISTService.map_controls |
| GET | `/nist/controls` | NISTService.get_controls_status |
| POST | `/cmmc/assess` | CMMCService.assess |
| GET | `/cmmc/level/{level}` | CMMCService.get_level_status |
| POST | `/sovereign/deploy` | SovereignCloudService.deploy |
| GET | `/il-level/{level}/status` | SovereignCloudService + ClassifiedEnvService |

## Services

- **FedRAMPService**: Readiness scoring, authorization workflow progression
- **NISTService**: Bulk control mapping, status tracking, completion reporting
- **CMMCService**: Practice gap analysis, SPRS-style scoring, C3PAO workflow
- **SovereignCloudService**: Cloud provisioning orchestration, IL level filtering
- **ClassifiedEnvService**: Air-gapped env config, IL4/IL5 strict controls

## Kafka Events Published

- `fedramp.assessment.completed` → `Topics.COMPLIANCE_EVENTS`
- `nist.controls.mapped` → `Topics.COMPLIANCE_EVENTS`
- `cmmc.assessment.completed` → `Topics.COMPLIANCE_EVENTS`
- `sovereign.deployment.initiated` → `Topics.DEPLOYMENT_EVENTS`
- `classified_env.configured` → `Topics.COMPLIANCE_EVENTS`

## Compliance Notes

- Never log classified data or CUI in plain text — use structured logging with masked fields
- IL5 environments require encryption at rest with tenant-managed KMS keys
- Air-gapped environments must not initiate outbound network connections
- FedRAMP assessments require PMO review before status advances to AUTHORIZED
- CMMC Level 2+ requires C3PAO assessment (not self-attestation)

## What Claude Code Should NOT Do

1. Do NOT reimplement anything in aumos-common
2. Do NOT log raw CUI or classified data values — mask sensitive fields
3. Do NOT hardcode compliance thresholds — use settings with env vars
4. Do NOT skip type hints on any function
5. Do NOT return raw dicts from API endpoints
6. Do NOT write raw SQL — use SQLAlchemy ORM with BaseRepository
7. Do NOT advance authorization status without proper workflow checks
8. Do NOT store encryption keys in plaintext — reference ARNs only
