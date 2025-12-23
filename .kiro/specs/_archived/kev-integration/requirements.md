# CISA KEV Integration Requirements

## Introduction

This specification outlines the integration of CISA's Known Exploited Vulnerabilities (KEV) catalog into the ROTA system. KEV provides government-verified data on CVEs that have been actively exploited in the wild, offering a ground truth for actual exploitation risk beyond EPSS predictions.

## Glossary

- **KEV**: Known Exploited Vulnerabilities - CISA's catalog of CVEs with confirmed real-world exploitation
- **CISA**: Cybersecurity and Infrastructure Security Agency - US government agency
- **ROTA System**: The vulnerability prediction and analysis system
- **CVE**: Common Vulnerabilities and Exposures identifier
- **EPSS**: Exploit Prediction Scoring System - probabilistic exploitation score

## Requirements

### Requirement 1: KEV Data Collection

**User Story:** As a security researcher, I want to collect CISA KEV data so that I can identify CVEs with confirmed real-world exploitation.

#### Acceptance Criteria

1. WHEN the KEV collector is invoked, THE System SHALL fetch the latest KEV catalog from CISA's official JSON endpoint
2. THE System SHALL parse KEV entries containing CVE ID, vulnerability name, vendor/product, date added, required action, and due date
3. THE System SHALL store KEV data in JSONL format with timestamp metadata
4. THE System SHALL handle network errors gracefully with retry logic and informative error messages
5. THE System SHALL complete data collection for the entire KEV catalog in less than 60 seconds

### Requirement 2: KEV Data Validation

**User Story:** As a data engineer, I want KEV data to be validated so that downstream analysis uses only high-quality data.

#### Acceptance Criteria

1. THE System SHALL verify that each KEV entry contains a valid CVE ID matching the pattern CVE-YYYY-NNNNN
2. THE System SHALL validate that the date_added field is a valid ISO 8601 date
3. WHEN duplicate CVE IDs are encountered, THE System SHALL keep the most recent entry
4. THE System SHALL log validation warnings for entries with missing optional fields
5. THE System SHALL reject entries with missing required fields (cveID, vulnerabilityName, dateAdded)

### Requirement 3: Neo4j Integration

**User Story:** As a data analyst, I want KEV data loaded into Neo4j so that I can query exploitation relationships in the knowledge graph.

#### Acceptance Criteria

1. THE System SHALL create KEV nodes in Neo4j with properties: cve_id, vulnerability_name, vendor_project, product, date_added, short_description, required_action, due_date, known_ransomware_use
2. THE System SHALL create HAS_KEV relationships between CVE nodes and KEV nodes
3. THE System SHALL create indexes on cve_id and date_added fields for query performance
4. WHEN a KEV entry already exists for a CVE, THE System SHALL update the existing node rather than create duplicates
5. THE System SHALL complete Neo4j loading for 1000+ KEV entries in less than 5 minutes

### Requirement 4: KEV Enrichment

**User Story:** As a threat analyst, I want CVE data enriched with KEV status so that I can prioritize vulnerabilities with confirmed exploitation.

#### Acceptance Criteria

1. THE System SHALL add a boolean is_kev flag to CVE nodes when a matching KEV entry exists
2. THE System SHALL calculate days_to_exploitation as the difference between CVE published date and KEV date_added
3. THE System SHALL identify ransomware-associated vulnerabilities using the known_ransomware_use field
4. THE System SHALL provide a query interface to filter CVEs by KEV status
5. THE System SHALL update KEV enrichment data when new KEV entries are added

### Requirement 5: KEV Analytics

**User Story:** As a security researcher, I want KEV analytics so that I can understand exploitation patterns and validate prediction models.

#### Acceptance Criteria

1. THE System SHALL calculate the percentage of CVEs in the dataset that appear in KEV
2. THE System SHALL compute the distribution of days_to_exploitation for KEV entries
3. THE System SHALL identify the most common vendors/products in KEV
4. THE System SHALL compare EPSS scores for KEV vs non-KEV CVEs
5. THE System SHALL generate a KEV statistics report in JSON format

### Requirement 6: Temporal Validation Support

**User Story:** As a machine learning engineer, I want KEV data with temporal awareness so that I can perform historical validation without data leakage.

#### Acceptance Criteria

1. THE System SHALL preserve the date_added timestamp for each KEV entry
2. THE System SHALL support temporal queries to retrieve KEV status as of a specific date
3. WHEN performing historical validation, THE System SHALL only use KEV entries added before the cutoff date
4. THE System SHALL provide a method to simulate KEV status at any historical point in time
5. THE System SHALL document temporal validation procedures in the codebase

### Requirement 7: CLI Integration

**User Story:** As a developer, I want KEV collection integrated into the CLI so that I can easily collect and load KEV data.

#### Acceptance Criteria

1. THE System SHALL provide a `rota collect kev` command to fetch KEV data
2. THE System SHALL provide a `rota load kev` command to load KEV data into Neo4j
3. THE System SHALL support a `--output` flag to specify the output directory
4. THE System SHALL display progress information during collection and loading
5. THE System SHALL return appropriate exit codes for success (0) and failure (non-zero)

### Requirement 8: Documentation

**User Story:** As a new contributor, I want clear documentation so that I can understand and use the KEV integration.

#### Acceptance Criteria

1. THE System SHALL include docstrings for all public KEV-related functions
2. THE System SHALL provide a README section explaining KEV integration
3. THE System SHALL include example usage in the documentation
4. THE System SHALL document the KEV data schema and Neo4j structure
5. THE System SHALL provide troubleshooting guidance for common issues

## Data Source

- **Official KEV Catalog**: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **Update Frequency**: Daily (CISA updates as new exploited vulnerabilities are identified)
- **Data Format**: JSON with array of vulnerability objects
- **License**: Public domain (US government data)

## Success Metrics

- **Collection Time**: < 60 seconds for full KEV catalog
- **Data Quality**: 100% of entries pass validation
- **Neo4j Load Time**: < 5 minutes for 1000+ entries
- **Query Performance**: < 100ms for KEV status lookup
- **Coverage**: Match 100% of KEV CVEs with existing CVE nodes

## Dependencies

- CISA KEV JSON endpoint availability
- Existing CVE data in Neo4j
- Network connectivity for API access
- Neo4j database running and accessible

## Constraints

- Must not modify existing CVE data structure
- Must maintain temporal integrity for historical validation
- Must handle CISA API rate limits gracefully
- Must be compatible with existing data collection pipeline
