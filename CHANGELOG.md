# Changelog

All notable changes to LLMDump will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2025-10-27

### Changed
- Cleaned up and reorganized all documentation
- Standardized file naming to lowercase-with-dashes convention
- Removed outdated Korean documentation and duplicate guides
- Updated graphiti-comparison.md to reflect current LLMDump architecture
- Consolidated release guides into comprehensive release-guide.md

### Added
- Automated release creation workflow
- Release creation scripts (PowerShell and Bash)
- Comprehensive release management guide

### Removed
- Outdated implementation summaries and refactoring plans
- Duplicate publish/release guides
- Korean paper experiment documentation
- Empty guide files

## [0.1.3] - 2025-10-27

### Changed
- Reorganized documentation into `/docs/guides` and `/docs/paper` subdirectories
- Translated all Korean documentation to English
- Reorganized scripts into `/scripts/collection`, `/loading`, `/experiments`, `/deployment`, `/archive`
- Added README.md to docs/ and scripts/ directories for better navigation
- Cleaned up root directory (removed temporary files)
- Updated GitHub Actions to auto-publish to PyPI on main branch changes

### Added
- Documentation structure guide in docs/README.md
- Scripts organization guide in scripts/README.md

## [0.1.1] - 2025-10-27

### Fixed
- Version bump for PyPI release (0.1.0 filename was previously used)

## [0.1.0] - 2025-10-16

### Added
- Initial release of LLMDump
- LLM-powered zero-day vulnerability prediction system
- Real-time code push analysis (< 10 seconds)
- Historical validation framework with CVE data
- Multi-source data collection (CVE, GitHub, EPSS, Exploit-DB)
- Command-line interface (`llmdump` command)
- Python API for programmatic access
- CI/CD integration support
- Comprehensive evaluation framework
- Performance optimization with caching
- Neo4j integration for graph-based analysis
- Streamlit dashboard for visualization

### Features
- **Data Collection**: Automated collection from 8+ security data sources
- **Prediction Engine**: GitHub activity pattern analysis
- **Feature Engineering**: 20+ behavioral and temporal features
- **Evaluation**: Historical validation on 80+ real CVEs
- **Performance**: Optimized for real-time CI/CD integration
- **Extensibility**: Modular architecture for easy extension

### Technical Details
- Python 3.10+ support
- Modern packaging with pyproject.toml
- Type hints throughout codebase
- Comprehensive test coverage
- Documentation and examples
- MIT license

### Known Limitations
- Currently focused on GitHub repositories
- Requires GitHub API token for full functionality
- Historical validation can be slow for large datasets
- Limited to English language repositories

### Future Plans
- GraphQL API integration for better performance
- Support for additional version control systems
- Enhanced machine learning models
- Real-time dashboard improvements
- Enterprise features and support