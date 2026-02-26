# aumos-govdef-overlay

Government/Defense compliance vertical overlay for AumOS Enterprise.

Provides FedRAMP authorization lifecycle management, NIST SP 800-53 control mapping,
CMMC Level 3 assessment, sovereign cloud deployment (AWS GovCloud / Azure Government /
GCC High), and IL4/IL5 air-gapped classified environment management.

## Features

- **FedRAMP**: Readiness assessment scoring, authorization workflow tracking, ATO management
- **NIST 800-53**: Bulk control mapping (Rev 4 & Rev 5), evidence tracking, completion reporting
- **CMMC**: Practice gap analysis, SPRS-style scoring, C3PAO workflow support (Levels 1-3)
- **Sovereign Cloud**: Deployment orchestration with compliance framework enforcement
- **IL4/IL5**: Air-gapped classified environment configuration and status tracking
- **Cross-framework Mapping**: FedRAMP ↔ NIST ↔ CMMC ↔ DoD IL level gap analysis

## API

```
POST   /api/v1/govdef/fedramp/assess           # FedRAMP readiness assessment
GET    /api/v1/govdef/fedramp/status            # Authorization status by agency
POST   /api/v1/govdef/nist/map                  # Bulk NIST 800-53 control mapping
GET    /api/v1/govdef/nist/controls             # Control implementation status
POST   /api/v1/govdef/cmmc/assess               # CMMC practice gap assessment
GET    /api/v1/govdef/cmmc/level/{level}        # Level compliance status
POST   /api/v1/govdef/sovereign/deploy          # Sovereign cloud deployment
GET    /api/v1/govdef/il-level/{level}/status   # IL4/IL5 status across all assets
```

## Quick Start

```bash
cp .env.example .env
make install
make docker-run   # starts postgres + kafka + service
```

## Development

```bash
make install      # install with dev dependencies
make test         # run tests with coverage
make lint         # ruff check + format check
make typecheck    # mypy strict mode
make format       # auto-fix formatting
```

## Database Tables

| Table | Description |
|-------|-------------|
| `gdf_fedramp_assessments` | FedRAMP readiness and authorization records |
| `gdf_nist_controls` | NIST 800-53 control mapping status per tenant |
| `gdf_cmmc_assessments` | CMMC level assessments and practice scoring |
| `gdf_sovereign_deployments` | Sovereign cloud deployment configurations |
| `gdf_classified_environments` | Air-gapped IL4/IL5 environment configs |

## Architecture

Hexagonal architecture with three layers:

- `api/` — FastAPI routes and Pydantic schemas (thin, delegates to services)
- `core/` — Domain models, services, and Protocol interfaces (no framework deps)
- `adapters/` — SQLAlchemy repositories, Kafka publisher, compliance mapper

## License

Apache-2.0 — Copyright AumOS Enterprise
