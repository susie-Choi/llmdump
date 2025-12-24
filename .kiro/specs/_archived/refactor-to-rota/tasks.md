# ROTA Architecture Refactoring Tasks

## Overview

Implementation tasks for refactoring `zero_day_defense` to clean ROTA architecture. This refactoring will simplify the codebase, improve maintainability, and align with research goals.

**Estimated Total Time**: 5-6 days
**Priority**: P0 (Critical - Foundation for all future work)

## Task List

- [x] 1. Create ROTA package structure


  - Set up new directory structure
  - Create all module directories
  - Initialize package files
  - _Requirements: 1.1, 1.2_



- [ ] 1.1 Create main package structure
  - Create `src/rota/` directory
  - Create `__init__.py` with version info
  - Create `__version__.py`
  - Create `config.py` for configuration


  - _Requirements: 1.1, 1.2_

- [ ] 1.2 Create module directories
  - Create `src/rota/spokes/` with `__init__.py`
  - Create `src/rota/hub/` with `__init__.py`
  - Create `src/rota/wheel/` with `__init__.py`
  - Create `src/rota/oracle/` with `__init__.py`
  - Create `src/rota/axle/` with `__init__.py`


  - Create `src/rota/cli/` with `__init__.py`
  - Create `src/rota/utils/` with `__init__.py`
  - _Requirements: 1.2_




- [ ] 1.3 Update package configuration
  - Update `pyproject.toml` with new package name
  - Update entry points for CLI
  - Update package metadata
  - Set version to 0.2.0
  - _Requirements: 9.1, 9.2, 9.3, 9.4_



- [ ] 2. Migrate Spokes module (Data Collection)
  - Create base collector class
  - Migrate all data collectors
  - Add KEV collector


  - Update imports
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [ ] 2.1 Create base collector
  - Create `src/rota/spokes/base.py`

  - Implement BaseCollector abstract class
  - Add common methods (save_jsonl, validate, etc.)
  - Add logging utilities
  - _Requirements: 2.4, 2.5_


- [ ] 2.2 Migrate CVE collector
  - Copy `zero_day_defense/data_sources/cve.py` to `rota/spokes/cve.py`
  - Update to inherit from BaseCollector
  - Update imports
  - Simplify code

  - _Requirements: 2.1, 2.2_

- [ ] 2.3 Migrate EPSS collector
  - Copy `zero_day_defense/data_sources/epss.py` to `rota/spokes/epss.py`
  - Update to inherit from BaseCollector

  - Update imports
  - _Requirements: 2.1, 2.2_

- [ ] 2.4 Migrate GitHub Advisory collector
  - Copy `zero_day_defense/data_sources/github_advisory.py` to `rota/spokes/advisory.py`
  - Update to inherit from BaseCollector

  - Update imports
  - _Requirements: 2.1, 2.2_

- [ ] 2.5 Migrate Exploit-DB collector
  - Copy `zero_day_defense/data_sources/exploit_db.py` to `rota/spokes/exploit_db.py`
  - Update to inherit from BaseCollector
  - Update imports
  - _Requirements: 2.1, 2.2_

- [ ] 2.6 Add KEV collector
  - Create `src/rota/spokes/kev.py`
  - Implement KEVCollector class
  - Add CISA API integration
  - Add validation logic
  - _Requirements: 2.2, 2.3_

- [ ] 2.7 Update spokes __init__.py
  - Export all collectors
  - Add convenience imports
  - Add module documentation
  - _Requirements: 2.1_

- [ ] 3. Migrate Hub module (Data Integration)
  - Create Neo4j connection management
  - Create data loaders
  - Migrate loading scripts
  - Add schema management
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 3.1 Create connection management
  - Create `src/rota/hub/connection.py`
  - Implement Neo4jConnection class
  - Add connection pooling
  - Add context manager support
  - _Requirements: 3.1, 3.4_

- [ ] 3.2 Create data loader
  - Create `src/rota/hub/loader.py`
  - Implement DataLoader class
  - Add methods for each data type (CVE, EPSS, KEV, etc.)
  - Add batch processing
  - _Requirements: 3.2_

- [ ] 3.3 Create schema management
  - Create `src/rota/hub/schema.py`
  - Add index creation methods
  - Add constraint management
  - Add schema migration support
  - _Requirements: 3.5_

- [ ] 3.4 Create query utilities
  - Create `src/rota/hub/queries.py`
  - Add common graph queries
  - Add query builders
  - Add result parsers
  - _Requirements: 3.3_

- [ ] 3.5 Migrate loading scripts
  - Extract logic from `scripts/load_*_to_neo4j.py`
  - Integrate into DataLoader
  - Update scripts to use hub module
  - _Requirements: 3.2_

- [ ] 4. Migrate Wheel module (Clustering)
  - Create clusterer
  - Create feature extractor
  - Migrate clustering logic
  - Add visualization
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [ ] 4.1 Create clusterer
  - Create `src/rota/wheel/clusterer.py`
  - Implement VulnerabilityClusterer class
  - Support multiple clustering algorithms
  - Add cluster statistics
  - _Requirements: 4.1, 4.2_

- [ ] 4.2 Create feature extractor
  - Create `src/rota/wheel/features.py`
  - Implement FeatureExtractor class
  - Add CVE feature extraction
  - Add CWE encoding
  - _Requirements: 4.5_

- [ ] 4.3 Migrate clustering logic
  - Copy relevant code from `prediction/engine/clusterer.py`
  - Simplify and refactor
  - Update imports
  - _Requirements: 4.2_

- [ ] 4.4 Create pattern discovery
  - Create `src/rota/wheel/patterns.py`
  - Implement pattern discovery algorithms
  - Add pattern validation
  - _Requirements: 4.3_

- [ ] 4.5 Add visualization
  - Create `src/rota/wheel/visualizer.py`
  - Add cluster visualization methods
  - Add pattern visualization
  - _Requirements: 4.4_

- [ ] 5. Migrate Oracle module (Prediction)
  - Create predictor
  - Create risk scorer
  - Migrate prediction logic
  - Simplify agents
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [ ] 5.1 Create predictor
  - Create `src/rota/oracle/predictor.py`
  - Implement VulnerabilityPredictor class
  - Add single and batch prediction
  - Add confidence scoring
  - _Requirements: 5.1, 5.4_

- [ ] 5.2 Create risk scorer
  - Create `src/rota/oracle/scorer.py`
  - Implement RiskScorer class
  - Add multi-factor risk calculation
  - Add factor importance
  - _Requirements: 5.2_

- [ ] 5.3 Migrate data models
  - Copy `prediction/models.py` to `oracle/models.py`
  - Simplify data models
  - Update imports
  - _Requirements: 5.3_

- [ ] 5.4 Simplify agents (optional)
  - Create `src/rota/oracle/agents.py`
  - Keep only essential LLM agent code
  - Make agents optional
  - _Requirements: 5.4_

- [ ] 5.5 Create prediction API
  - Add clear prediction interface
  - Add result formatting
  - Add error handling
  - _Requirements: 5.4_

- [ ] 6. Migrate Axle module (Evaluation)
  - Create validator
  - Create metrics calculator
  - Migrate evaluation logic
  - Add baselines
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [ ] 6.1 Create temporal validator
  - Create `src/rota/axle/validator.py`
  - Implement TemporalValidator class
  - Add data leakage prevention
  - Add temporal queries
  - _Requirements: 6.1, 6.3_

- [ ] 6.2 Create metrics calculator
  - Create `src/rota/axle/metrics.py`
  - Implement common metrics (precision, recall, F1)
  - Add lead time calculation
  - Add statistical tests
  - _Requirements: 6.2, 6.4_

- [ ] 6.3 Migrate evaluation logic
  - Copy relevant code from `evaluation/`
  - Simplify and refactor
  - Update imports
  - _Requirements: 6.2_

- [ ] 6.4 Create baseline comparisons
  - Create `src/rota/axle/baselines.py`
  - Implement baseline predictors (random, CVSS, EPSS)
  - Add comparison utilities
  - _Requirements: 6.5_

- [ ] 6.5 Create statistics module
  - Create `src/rota/axle/statistics.py`
  - Add dataset statistics
  - Add result analysis
  - _Requirements: 6.4_

- [ ] 7. Create new CLI
  - Design CLI structure
  - Implement command groups
  - Migrate existing commands
  - Add new commands
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5_

- [ ] 7.1 Create main CLI entry point
  - Create `src/rota/cli/main.py`
  - Set up Click command groups
  - Add version option
  - Add global options
  - _Requirements: 8.1, 8.3_

- [ ] 7.2 Create spokes commands
  - Create `src/rota/cli/spokes_cmd.py`
  - Add collect commands for each data source
  - Add list and status commands
  - _Requirements: 8.2_

- [ ] 7.3 Create hub commands
  - Create `src/rota/cli/hub_cmd.py`
  - Add load commands
  - Add status and query commands
  - Add schema management commands
  - _Requirements: 8.2_

- [ ] 7.4 Create wheel commands
  - Create `src/rota/cli/wheel_cmd.py`
  - Add cluster command
  - Add pattern discovery command
  - Add visualization command
  - _Requirements: 8.2_

- [ ] 7.5 Create oracle commands
  - Create `src/rota/cli/oracle_cmd.py`
  - Add predict command
  - Add scan command
  - Add batch prediction command
  - _Requirements: 8.2_

- [ ] 7.6 Create axle commands
  - Create `src/rota/cli/axle_cmd.py`
  - Add validate command
  - Add compare-baselines command
  - Add statistics command
  - _Requirements: 8.2_

- [ ] 7.7 Update CLI entry point in pyproject.toml
  - Update console_scripts entry point
  - Change from `zero-day-defense` to `rota`
  - _Requirements: 8.1, 9.3_

- [ ] 8. Add backward compatibility
  - Create compatibility shims
  - Add deprecation warnings
  - Update old imports
  - Test compatibility
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

- [ ] 8.1 Create compatibility package
  - Keep `src/zero_day_defense/` directory
  - Create `__init__.py` with import redirects
  - Add deprecation warnings
  - _Requirements: 11.1, 11.2_

- [ ] 8.2 Add import shims
  - Redirect `zero_day_defense.data_sources` to `rota.spokes`
  - Redirect `zero_day_defense.prediction` to `rota.oracle`
  - Redirect `zero_day_defense.evaluation` to `rota.axle`
  - _Requirements: 11.1_

- [ ] 8.3 Create migration script
  - Create `scripts/migrate_to_rota.py`
  - Automatically update imports in user code
  - Provide migration report
  - _Requirements: 11.5_

- [ ] 8.4 Create MIGRATION.md
  - Document migration steps
  - Provide code examples
  - List breaking changes
  - Add FAQ
  - _Requirements: 11.4_

- [ ] 9. Update tests
  - Update test imports
  - Reorganize test structure
  - Ensure all tests pass
  - Add new tests
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [ ] 9.1 Update test imports
  - Find and replace `zero_day_defense` with `rota`
  - Update module paths
  - Fix broken imports
  - _Requirements: 10.1_

- [ ] 9.2 Reorganize test structure
  - Create `tests/test_spokes/`
  - Create `tests/test_hub/`
  - Create `tests/test_wheel/`
  - Create `tests/test_oracle/`
  - Create `tests/test_axle/`
  - Move tests to appropriate directories
  - _Requirements: 10.2_

- [ ] 9.3 Run and fix tests
  - Run pytest
  - Fix failing tests
  - Update test data paths
  - Ensure 70%+ coverage
  - _Requirements: 10.3, 10.5_

- [ ] 9.4 Add integration tests
  - Create `tests/integration/test_rota_pipeline.py`
  - Test end-to-end workflows
  - Test module interactions
  - _Requirements: 10.4_

- [ ] 10. Consolidate documentation
  - Reorganize docs directory
  - Update all documentation
  - Create new guides
  - Archive old docs
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 12.1, 12.2, 12.3, 12.4, 12.5_

- [ ] 10.1 Create docs structure
  - Create `docs/modules/` directory
  - Create `docs/guides/` directory
  - Create `docs/api/` directory
  - Create `docs/research/` directory
  - Create `docs/archive/` directory
  - _Requirements: 7.2_

- [ ] 10.2 Write main documentation
  - Create `docs/README.md` as documentation hub
  - Create `docs/architecture.md` with ROTA overview
  - Create `docs/getting-started.md` with quick start
  - Add architecture diagrams
  - _Requirements: 7.1, 7.3, 12.1, 12.3_

- [ ] 10.3 Write module documentation
  - Create `docs/modules/spokes.md`
  - Create `docs/modules/hub.md`
  - Create `docs/modules/wheel.md`
  - Create `docs/modules/oracle.md`
  - Create `docs/modules/axle.md`
  - _Requirements: 7.3, 12.2_

- [ ] 10.4 Write guides
  - Create `docs/guides/data-collection.md`
  - Create `docs/guides/clustering.md`
  - Create `docs/guides/prediction.md`
  - Create `docs/guides/evaluation.md`
  - Add code examples
  - _Requirements: 7.3, 12.2_

- [ ] 10.5 Archive old documentation
  - Move `docs/WORK_SUMMARY.md` to `docs/archive/`
  - Move `docs/TODAY_ACHIEVEMENTS.md` to `docs/archive/`
  - Move other outdated docs to archive
  - Update README to point to new docs
  - _Requirements: 7.2_

- [ ] 10.6 Update root README
  - Rewrite README.md for ROTA
  - Add architecture overview
  - Add installation instructions
  - Add quick start examples
  - Add links to detailed docs
  - _Requirements: 7.1, 7.3_

- [ ] 10.7 Clean up root directory
  - Move `QUICKSTART.md` content to `docs/getting-started.md`
  - Move `TEMPORAL_SETUP.md` to `docs/guides/`
  - Move `HOW_TO_PUBLISH.md` to `docs/development/`
  - Keep only essential files in root
  - _Requirements: 7.2_

- [ ] 11. Update scripts
  - Update all scripts to use ROTA
  - Simplify scripts using new modules
  - Add new utility scripts
  - _Requirements: 8.5_

- [ ] 11.1 Update collection scripts
  - Update `scripts/collect_cve_data.py` to use `rota.spokes`
  - Update `scripts/collect_epss.py`
  - Update `scripts/collect_github_advisory.py`
  - Update `scripts/collect_exploits.py`
  - _Requirements: 8.5_

- [ ] 11.2 Update loading scripts
  - Update `scripts/load_cve_to_neo4j.py` to use `rota.hub`
  - Update `scripts/load_epss_to_neo4j.py`
  - Update `scripts/load_advisory_to_neo4j.py`
  - Update `scripts/load_exploits_to_neo4j.py`
  - _Requirements: 8.5_

- [ ] 11.3 Update prediction scripts
  - Update `scripts/run_prediction_demo.py` to use `rota.oracle`
  - Update `scripts/test_prediction_concept.py`
  - _Requirements: 8.5_

- [ ] 11.4 Update evaluation scripts
  - Update `scripts/historical_validation.py` to use `rota.axle`
  - Update `scripts/run_historical_validation.py`
  - _Requirements: 8.5_

- [ ] 12. Final validation
  - Run all tests
  - Test package installation
  - Test CLI commands
  - Verify backward compatibility
  - _Requirements: All_

- [ ] 12.1 Run full test suite
  - Run `pytest tests/`
  - Verify 70%+ coverage
  - Fix any failing tests
  - _Requirements: 10.3, 10.5_

- [ ] 12.2 Test package installation
  - Build package: `python -m build`
  - Install in clean environment: `pip install dist/rota-0.2.0-*.whl`
  - Test imports
  - Test CLI commands
  - _Requirements: 9.1, 9.2, 9.3_

- [ ] 12.3 Test backward compatibility
  - Test old imports with deprecation warnings
  - Test old CLI commands
  - Verify compatibility shims work
  - _Requirements: 11.1, 11.2, 11.3_

- [ ] 12.4 Create release checklist
  - Update CHANGELOG.md
  - Create release notes
  - Tag version 0.2.0
  - Prepare PyPI release
  - _Requirements: 9.4_

## Implementation Order

### Day 1: Structure Setup
- Task 1: Create ROTA package structure (2 hours)
- Task 2: Migrate Spokes module (4 hours)

### Day 2: Hub and Wheel
- Task 3: Migrate Hub module (3 hours)
- Task 4: Migrate Wheel module (3 hours)

### Day 3: Oracle and Axle
- Task 5: Migrate Oracle module (3 hours)
- Task 6: Migrate Axle module (3 hours)

### Day 4: CLI and Compatibility
- Task 7: Create new CLI (3 hours)
- Task 8: Add backward compatibility (3 hours)

### Day 5: Tests and Documentation
- Task 9: Update tests (3 hours)
- Task 10: Consolidate documentation (4 hours)

### Day 6: Scripts and Validation
- Task 11: Update scripts (2 hours)
- Task 12: Final validation (4 hours)

## Success Criteria

- [ ] All code migrated to ROTA structure
- [ ] All tests passing with 70%+ coverage
- [ ] CLI working with new commands
- [ ] Backward compatibility maintained
- [ ] Documentation complete and clear
- [ ] Package builds and installs successfully
- [ ] Old imports work with deprecation warnings

## Notes

- **Incremental Migration**: Migrate one module at a time
- **Test Continuously**: Run tests after each module migration
- **Keep It Simple**: Remove unnecessary complexity during migration
- **Document Changes**: Update docs as you go
- **Backward Compatibility**: Ensure old code still works

## Next Steps After Completion

1. Release ROTA v0.2.0 to PyPI
2. Announce migration to users
3. Add KEV integration (now easier with clean structure)
4. Add CWE detailed data
5. Add vulnerable code collection
6. Focus on research contributions
