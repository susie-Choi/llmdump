# ROTA Architecture Refactoring Requirements

## Introduction

This specification outlines the refactoring of the current `zero_day_defense` codebase into a clean, research-focused ROTA (Rotating Threat Analysis) architecture. The goal is to simplify the codebase, improve maintainability, and align with the wheel metaphor that represents the system's design philosophy.

## Glossary

- **ROTA**: Rotating Threat Analysis - the new architecture name
- **Spokes**: Data collection modules (formerly data_sources)
- **Hub**: Central data integration layer (Neo4j graph database)
- **Wheel**: Clustering and pattern analysis (formerly prediction/engine)
- **Oracle**: Prediction and risk scoring (formerly prediction core)
- **Axle**: Evaluation and validation framework (formerly evaluation)
- **Legacy Code**: Current `zero_day_defense` package structure

## Requirements

### Requirement 1: Code Structure Migration

**User Story:** As a developer, I want a clean ROTA architecture so that the codebase is easier to understand and maintain.

#### Acceptance Criteria

1. THE System SHALL migrate all code from `src/zero_day_defense/` to `src/rota/`
2. THE System SHALL organize code into five main modules: spokes, hub, wheel, oracle, axle
3. THE System SHALL maintain backward compatibility during migration with deprecation warnings
4. THE System SHALL update all import statements to use the new structure
5. THE System SHALL remove the old `zero_day_defense` package after migration is complete

### Requirement 2: Spokes Module (Data Collection)

**User Story:** As a data engineer, I want all data collectors in one place so that I can easily add new data sources.

#### Acceptance Criteria

1. THE System SHALL create `src/rota/spokes/` module containing all data collectors
2. THE System SHALL migrate CVE, EPSS, GitHub Advisory, Exploit-DB collectors to spokes
3. THE System SHALL add KEV collector to spokes module
4. THE System SHALL provide a unified collector interface for all data sources
5. THE System SHALL include base collector class with common functionality

### Requirement 3: Hub Module (Data Integration)

**User Story:** As a data scientist, I want centralized data integration so that all data flows through a single graph database.

#### Acceptance Criteria

1. THE System SHALL create `src/rota/hub/` module for Neo4j integration
2. THE System SHALL consolidate all Neo4j loading scripts into hub module
3. THE System SHALL provide graph query utilities in hub module
4. THE System SHALL implement connection management and pooling
5. THE System SHALL include schema management and migration tools

### Requirement 4: Wheel Module (Clustering & Patterns)

**User Story:** As a researcher, I want clustering and pattern analysis in one module so that I can focus on vulnerability patterns.

#### Acceptance Criteria

1. THE System SHALL create `src/rota/wheel/` module for clustering and patterns
2. THE System SHALL migrate clustering logic from prediction/engine to wheel
3. THE System SHALL implement pattern discovery algorithms in wheel
4. THE System SHALL provide visualization utilities for clusters
5. THE System SHALL include feature extraction for clustering

### Requirement 5: Oracle Module (Prediction)

**User Story:** As a security analyst, I want prediction logic separated from data processing so that I can focus on risk assessment.

#### Acceptance Criteria

1. THE System SHALL create `src/rota/oracle/` module for prediction
2. THE System SHALL migrate prediction logic from prediction/ to oracle
3. THE System SHALL implement risk scoring in oracle module
4. THE System SHALL provide prediction API with clear interfaces
5. THE System SHALL include model management and versioning

### Requirement 6: Axle Module (Evaluation)

**User Story:** As a researcher, I want evaluation tools in one place so that I can validate my models properly.

#### Acceptance Criteria

1. THE System SHALL create `src/rota/axle/` module for evaluation
2. THE System SHALL migrate evaluation code from evaluation/ to axle
3. THE System SHALL implement temporal validation in axle
4. THE System SHALL provide metrics calculation utilities
5. THE System SHALL include baseline comparison tools

### Requirement 7: Documentation Consolidation

**User Story:** As a new contributor, I want clear, organized documentation so that I can quickly understand the project.

#### Acceptance Criteria

1. THE System SHALL consolidate documentation into `docs/` directory with clear structure
2. THE System SHALL archive outdated documentation in `docs/archive/`
3. THE System SHALL create a main `docs/README.md` with navigation
4. THE System SHALL update all documentation to reflect ROTA architecture
5. THE System SHALL remove redundant root-level markdown files

### Requirement 8: CLI Refactoring

**User Story:** As a user, I want a simple CLI that reflects the ROTA architecture so that commands are intuitive.

#### Acceptance Criteria

1. THE System SHALL update CLI to use `rota` command instead of `zero-day-defense`
2. THE System SHALL organize CLI commands by module (spokes, hub, wheel, oracle, axle)
3. THE System SHALL provide clear help text for all commands
4. THE System SHALL maintain backward compatibility with deprecation warnings
5. THE System SHALL update all scripts to use new CLI commands

### Requirement 9: Package Configuration

**User Story:** As a maintainer, I want updated package configuration so that the new structure is properly packaged.

#### Acceptance Criteria

1. THE System SHALL update `pyproject.toml` to reflect ROTA package structure
2. THE System SHALL update package name from `zero-day-defense` to `rota`
3. THE System SHALL update entry points to use new CLI structure
4. THE System SHALL maintain version continuity (start from v0.2.0)
5. THE System SHALL update package metadata and description

### Requirement 10: Testing Migration

**User Story:** As a developer, I want all tests updated so that the refactored code is properly tested.

#### Acceptance Criteria

1. THE System SHALL update all test imports to use new ROTA structure
2. THE System SHALL organize tests by module (test_spokes, test_hub, etc.)
3. THE System SHALL ensure all existing tests pass after migration
4. THE System SHALL add integration tests for module interactions
5. THE System SHALL maintain test coverage above 70%

### Requirement 11: Backward Compatibility

**User Story:** As an existing user, I want my scripts to keep working so that I don't have to rewrite everything immediately.

#### Acceptance Criteria

1. THE System SHALL provide compatibility shims in `zero_day_defense` package
2. THE System SHALL emit deprecation warnings when old imports are used
3. THE System SHALL maintain compatibility for at least 2 minor versions
4. THE System SHALL document migration path in MIGRATION.md
5. THE System SHALL provide automated migration script

### Requirement 12: Documentation Quality

**User Story:** As a researcher, I want high-quality documentation so that I can understand the architecture and contribute effectively.

#### Acceptance Criteria

1. THE System SHALL include architecture diagrams in documentation
2. THE System SHALL provide code examples for each module
3. THE System SHALL document design decisions and rationale
4. THE System SHALL include API reference documentation
5. THE System SHALL provide contribution guidelines

## Success Metrics

- **Code Organization**: All code in appropriate ROTA modules
- **Import Statements**: 100% of imports updated to new structure
- **Test Coverage**: Maintained at 70%+ after refactoring
- **Documentation**: All docs updated and consolidated
- **Backward Compatibility**: Existing scripts work with deprecation warnings
- **Build Success**: Package builds and installs without errors

## Migration Strategy

### Phase 1: Structure Setup (Day 1)
- Create new ROTA module structure
- Set up empty modules with __init__.py files
- Update pyproject.toml

### Phase 2: Code Migration (Days 2-3)
- Migrate spokes (data collectors)
- Migrate hub (Neo4j integration)
- Migrate wheel (clustering)
- Migrate oracle (prediction)
- Migrate axle (evaluation)

### Phase 3: Integration (Day 4)
- Update CLI
- Update imports
- Add compatibility shims
- Update tests

### Phase 4: Documentation (Day 5)
- Consolidate documentation
- Update architecture docs
- Create migration guide
- Archive old docs

### Phase 5: Validation (Day 6)
- Run all tests
- Verify backward compatibility
- Test package installation
- Final cleanup

## Constraints

- Must maintain backward compatibility for 2 minor versions
- Must not break existing PyPI package (v0.1.1)
- Must preserve all existing functionality
- Must maintain or improve test coverage
- Must complete migration in 1 week

## Dependencies

- Existing `zero_day_defense` codebase
- All existing tests
- PyPI package infrastructure
- Documentation files

## Risks

- Breaking existing user scripts
- Import errors during migration
- Test failures
- Documentation gaps
- Package installation issues

## Mitigation

- Comprehensive testing at each phase
- Compatibility shims for old imports
- Automated migration script
- Clear deprecation warnings
- Detailed migration documentation
