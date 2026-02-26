# Changelog

All notable changes to aumos-govdef-overlay will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-26

### Added
- FedRAMP readiness assessment with scoring against NIST 800-53 control counts per impact level
- FedRAMP authorization workflow status tracking (NOT_STARTED through AUTHORIZED)
- NIST SP 800-53 Rev 5 bulk control mapping with bulk upsert support
- NIST control completion summary with status breakdown and percentages
- CMMC Level 1/2/3 assessment with SPRS-style scoring and domain breakdown
- CMMC C3PAO workflow support for Level 2+ assessments
- Sovereign cloud deployment configuration for AWS GovCloud, Azure Government, GCC High
- IL4/IL5 Impact Level status aggregation across deployments and environments
- Air-gapped classified environment configuration with encryption key ARN support
- Cross-framework compliance mapper (FedRAMP ↔ NIST ↔ CMMC ↔ DoD IL)
- Kafka event publishing for all compliance state transitions
- Full hexagonal architecture: api/, core/, adapters/
- PostgreSQL RLS tenant isolation on all `gdf_` tables
- Docker multi-stage build with non-root runtime user
- Comprehensive unit tests for all services and compliance mapper
