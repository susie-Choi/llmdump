# CISA KEV Integration Design

## Overview

This document outlines the technical design for integrating CISA's Known Exploited Vulnerabilities (KEV) catalog into ROTA. The integration follows the existing data source pattern and adds KEV as a ground truth signal for actual exploitation.

## Architecture

```
KEV Integration Flow
┌─────────────────────────────────────────────────────────────┐
│                     CISA KEV Catalog                        │
│         (known_exploited_vulnerabilities.json)              │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS GET
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              KEVCollector (data_sources/kev.py)             │
│  - Fetch JSON from CISA endpoint                            │
│  - Parse and validate entries                               │
│  - Save to JSONL format                                     │
└────────────────────┬────────────────────────────────────────┘
                     │ JSONL files
                     ▼
┌─────────────────────────────────────────────────────────────┐
│           KEVLoader (scripts/load_kev_to_neo4j.py)          │
│  - Read JSONL files                                         │
│  - Create KEV nodes                                         │
│  - Link to CVE nodes                                        │
│  - Add enrichment flags                                     │
└────────────────────┬────────────────────────────────────────┘
                     │ Cypher queries
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                      Neo4j Graph DB                         │
│  ┌──────────┐  HAS_KEV   ┌──────────┐                      │
│  │   CVE    │──────────▶ │   KEV    │                      │
│  │ is_kev=T │            │ date_added│                      │
│  └──────────┘            └──────────┘                      │
└─────────────────────────────────────────────────────────────┘
```

## Components and Interfaces

### 1. KEVCollector Class

**Location**: `src/zero_day_defense/data_sources/kev.py`

```python
class KEVCollector:
    """
    Collector for CISA Known Exploited Vulnerabilities catalog.
    
    Fetches and processes the official KEV JSON feed from CISA,
    providing ground truth data on actively exploited CVEs.
    """
    
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self, output_dir: str = "data/raw/kev"):
        """
        Initialize KEV collector.
        
        Args:
            output_dir: Directory to save collected KEV data
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ROTA-Research/0.1.1'
        })
    
    def collect(self) -> Dict[str, Any]:
        """
        Collect KEV catalog from CISA.
        
        Returns:
            Dictionary with collection statistics
            
        Raises:
            requests.RequestException: If API request fails
            ValueError: If response format is invalid
        """
        
    def _fetch_kev_catalog(self) -> Dict[str, Any]:
        """Fetch KEV JSON from CISA endpoint with retry logic."""
        
    def _validate_entry(self, entry: Dict[str, Any]) -> bool:
        """Validate a single KEV entry."""
        
    def _save_to_jsonl(self, entries: List[Dict[str, Any]]) -> Path:
        """Save KEV entries to JSONL file."""
```

**Key Methods**:
- `collect()`: Main entry point for KEV collection
- `_fetch_kev_catalog()`: HTTP request with retry logic
- `_validate_entry()`: Data validation for each entry
- `_save_to_jsonl()`: Persist data in JSONL format

### 2. KEV Data Model

```python
@dataclass
class KEVEntry:
    """Represents a CISA KEV catalog entry."""
    
    cve_id: str
    vulnerability_name: str
    vendor_project: str
    product: str
    date_added: datetime
    short_description: str
    required_action: str
    due_date: Optional[datetime]
    known_ransomware_use: bool
    notes: Optional[str]
    
    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'KEVEntry':
        """Parse KEV entry from CISA JSON format."""
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSONL storage."""
        
    def to_neo4j_properties(self) -> Dict[str, Any]:
        """Convert to Neo4j node properties."""
```

### 3. Neo4j Schema

**KEV Node**:
```cypher
CREATE (k:KEV {
    cve_id: "CVE-2024-1234",
    vulnerability_name: "Example Vulnerability",
    vendor_project: "vendor",
    product: "product_name",
    date_added: datetime("2024-01-15"),
    short_description: "Description text",
    required_action: "Apply updates per vendor instructions",
    due_date: datetime("2024-02-15"),
    known_ransomware_use: false,
    notes: "Additional context",
    collected_at: datetime()
})
```

**Relationships**:
```cypher
// Link CVE to KEV
MATCH (c:CVE {id: "CVE-2024-1234"})
MATCH (k:KEV {cve_id: "CVE-2024-1234"})
CREATE (c)-[:HAS_KEV]->(k)

// Add enrichment flag to CVE
MATCH (c:CVE {id: "CVE-2024-1234"})
SET c.is_kev = true,
    c.kev_date_added = datetime("2024-01-15"),
    c.kev_ransomware = false
```

**Indexes**:
```cypher
CREATE INDEX kev_cve_id IF NOT EXISTS FOR (k:KEV) ON (k.cve_id);
CREATE INDEX kev_date_added IF NOT EXISTS FOR (k:KEV) ON (k.date_added);
CREATE INDEX cve_is_kev IF NOT EXISTS FOR (c:CVE) ON (c.is_kev);
```

### 4. KEVLoader Script

**Location**: `scripts/load_kev_to_neo4j.py`

```python
class KEVLoader:
    """Load KEV data into Neo4j graph database."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """Initialize Neo4j connection."""
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
    
    def load_kev_data(self, jsonl_path: Path) -> Dict[str, int]:
        """
        Load KEV data from JSONL file into Neo4j.
        
        Returns:
            Statistics: nodes_created, relationships_created, cves_enriched
        """
        
    def _create_kev_node(self, tx, entry: KEVEntry) -> None:
        """Create or update KEV node in Neo4j."""
        
    def _link_to_cve(self, tx, cve_id: str) -> bool:
        """Create HAS_KEV relationship and enrich CVE node."""
        
    def _create_indexes(self) -> None:
        """Create necessary indexes for KEV queries."""
        
    def _calculate_days_to_exploitation(self, tx, cve_id: str, kev_date: datetime) -> Optional[int]:
        """Calculate days between CVE publication and KEV addition."""
```

### 5. CLI Integration

**Location**: `src/zero_day_defense/cli.py`

```python
@cli.command()
@click.option('--output', default='data/raw/kev', help='Output directory')
def collect_kev(output: str):
    """Collect CISA Known Exploited Vulnerabilities catalog."""
    collector = KEVCollector(output_dir=output)
    stats = collector.collect()
    click.echo(f"✓ Collected {stats['total_entries']} KEV entries")
    click.echo(f"✓ Saved to {stats['output_file']}")

@cli.command()
@click.option('--input', default='data/raw/kev', help='Input directory')
@click.option('--neo4j-uri', envvar='NEO4J_URI', required=True)
@click.option('--neo4j-user', envvar='NEO4J_USER', default='neo4j')
@click.option('--neo4j-password', envvar='NEO4J_PASSWORD', required=True)
def load_kev(input: str, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
    """Load KEV data into Neo4j."""
    loader = KEVLoader(neo4j_uri, neo4j_user, neo4j_password)
    stats = loader.load_kev_data(Path(input))
    click.echo(f"✓ Created {stats['nodes_created']} KEV nodes")
    click.echo(f"✓ Enriched {stats['cves_enriched']} CVE nodes")
```

## Data Flow

### Collection Flow

1. **Fetch**: HTTP GET request to CISA KEV endpoint
2. **Parse**: Extract vulnerability entries from JSON response
3. **Validate**: Check required fields and data formats
4. **Transform**: Convert to standardized KEVEntry objects
5. **Save**: Write to JSONL file with timestamp

### Loading Flow

1. **Read**: Parse JSONL file into KEVEntry objects
2. **Create Nodes**: Insert or update KEV nodes in Neo4j
3. **Link CVEs**: Create HAS_KEV relationships
4. **Enrich**: Add is_kev flag and metadata to CVE nodes
5. **Index**: Ensure indexes exist for query performance

### Query Flow

```python
# Example: Get all KEV CVEs
def get_kev_cves(tx) -> List[str]:
    query = """
    MATCH (c:CVE)-[:HAS_KEV]->(k:KEV)
    RETURN c.id as cve_id, k.date_added as exploited_date
    ORDER BY k.date_added DESC
    """
    result = tx.run(query)
    return [record["cve_id"] for record in result]

# Example: Compare EPSS for KEV vs non-KEV
def compare_epss_by_kev_status(tx) -> Dict[str, float]:
    query = """
    MATCH (c:CVE)-[:HAS_EPSS]->(e:EPSS)
    WITH c.is_kev as is_kev, avg(e.score) as avg_epss
    RETURN is_kev, avg_epss
    """
    result = tx.run(query)
    return {record["is_kev"]: record["avg_epss"] for record in result}
```

## Error Handling

### Network Errors
- Implement exponential backoff retry (3 attempts)
- Timeout after 30 seconds per request
- Log detailed error messages
- Graceful degradation if CISA endpoint is unavailable

### Data Validation Errors
- Log warnings for entries with missing optional fields
- Skip entries with invalid CVE IDs
- Continue processing remaining entries
- Report validation statistics at end

### Neo4j Errors
- Transaction rollback on failure
- Retry logic for transient errors
- Clear error messages for connection issues
- Validate Neo4j connection before bulk operations

## Testing Strategy

### Unit Tests
```python
# tests/test_kev_collector.py
def test_validate_entry_valid():
    """Test validation of valid KEV entry."""
    
def test_validate_entry_missing_cve_id():
    """Test validation rejects entry without CVE ID."""
    
def test_parse_date_formats():
    """Test parsing of various date formats."""

# tests/test_kev_loader.py
def test_create_kev_node():
    """Test KEV node creation in Neo4j."""
    
def test_link_to_existing_cve():
    """Test linking KEV to existing CVE node."""
    
def test_enrich_cve_with_kev_flag():
    """Test adding is_kev flag to CVE."""
```

### Integration Tests
```python
# tests/integration/test_kev_pipeline.py
def test_end_to_end_kev_collection():
    """Test complete KEV collection and loading pipeline."""
    
def test_temporal_validation_with_kev():
    """Test that KEV data respects temporal cutoffs."""
```

### Performance Tests
- Collection time < 60 seconds for full catalog
- Loading time < 5 minutes for 1000+ entries
- Query time < 100ms for KEV status lookup

## Performance Considerations

### Collection Optimization
- Single HTTP request for entire catalog
- Streaming JSON parsing for large responses
- Batch writing to JSONL file

### Loading Optimization
- Batch Neo4j transactions (100 entries per transaction)
- Parallel processing where possible
- Index creation before bulk loading
- MERGE instead of CREATE to handle duplicates

### Query Optimization
- Indexes on cve_id and date_added
- Denormalized is_kev flag on CVE nodes
- Materialized views for common analytics queries

## Security Considerations

- HTTPS for all CISA API requests
- Validate SSL certificates
- Sanitize input data before Neo4j queries
- Use parameterized Cypher queries to prevent injection
- Rate limiting to respect CISA infrastructure

## Monitoring and Logging

```python
import logging

logger = logging.getLogger(__name__)

# Collection metrics
logger.info(f"KEV collection started")
logger.info(f"Fetched {len(entries)} entries from CISA")
logger.warning(f"Skipped {invalid_count} invalid entries")
logger.info(f"Collection completed in {elapsed_time:.2f}s")

# Loading metrics
logger.info(f"Loading KEV data to Neo4j")
logger.info(f"Created {nodes_created} KEV nodes")
logger.info(f"Enriched {cves_enriched} CVE nodes")
logger.info(f"Loading completed in {elapsed_time:.2f}s")
```

## Future Enhancements

1. **Incremental Updates**: Only fetch new KEV entries since last collection
2. **Historical Snapshots**: Maintain KEV catalog history over time
3. **Notification System**: Alert when new KEV entries match monitored CVEs
4. **Trend Analysis**: Track KEV addition patterns over time
5. **Vendor Analysis**: Identify vendors with most KEV entries

## Dependencies

- `requests>=2.31.0`: HTTP client for CISA API
- `neo4j>=5.0.0`: Neo4j Python driver
- `click>=8.0.0`: CLI framework
- `python-dateutil>=2.8.0`: Date parsing

## Configuration

```yaml
# config/kev_config.yaml
kev:
  source_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  output_dir: "data/raw/kev"
  update_frequency: "daily"
  retry_attempts: 3
  timeout_seconds: 30
  
neo4j:
  batch_size: 100
  create_indexes: true
  enrich_cves: true
```

## Documentation

- Inline docstrings for all public functions
- README section on KEV integration
- Example Jupyter notebook for KEV analysis
- API documentation in Sphinx format
