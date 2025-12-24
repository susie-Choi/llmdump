---
inclusion: always
---

# Project Structure

## Directory Organization

```
llmdump/
├── .git/                       # Git repository
├── .kiro/                      # Kiro IDE configuration
│   ├── specs/                  # Feature specifications
│   └── steering/               # Development guidelines
├── config/                     # YAML configuration files
│   ├── cve_config.yaml
│   ├── epss_config.yaml
│   ├── exploit_config.yaml
│   └── github_advisory_config.yaml
├── data/                       # Data storage
│   ├── input/                  # Consolidated input data (JSONL)
│   ├── output/                 # Analysis results
│   └── raw/                    # Raw collected data
├── docs/                       # Documentation
│   ├── GUIDE.md
│   ├── DEVELOPMENT.md
│   ├── RESEARCH.md
│   └── paper/                  # Research paper materials
├── src/                        # Source code
│   ├── llmdump/                # Main package
│   │   ├── spokes/             # Data collectors
│   │   ├── hub/                # Neo4j integration
│   │   ├── oracle/             # Prediction & analysis
│   │   ├── axle/               # Evaluation framework
│   │   └── cli.py              # Command-line interface
│   └── scripts/                # Utility scripts
│       ├── collect_data.py
│       ├── load_to_neo4j.py
│       └── check_status.py
├── pyproject.toml              # Package configuration
├── requirements.txt            # Dependencies
└── README.md                   # Project overview
```

## Code Organization

### Package Structure
- **Package name**: `llmdump`
- **Layout**: Modern `src/` layout
- **Python version**: 3.10+

### Module Responsibilities

**spokes/** - Data Collection
- Each collector inherits from base classes
- Outputs JSONL format with consistent schema
- Handles API rate limiting and retries

**hub/** - Data Integration
- Neo4j connection management
- Data loading and schema management
- Graph query utilities

**oracle/** - Analysis & Prediction
- LLM code generation
- Vulnerability scanning
- Risk assessment

**axle/** - Evaluation
- Metrics calculation
- Baseline comparison
- Report generation

### Data Format

All collected data uses JSONL format:
```json
{
  "source": "cve",
  "id": "CVE-2024-12345",
  "collected_at": "2024-01-15T10:30:00Z",
  "payload": { ... }
}
```

### Configuration

- YAML-based configuration in `config/` directory
- Environment variables for sensitive data (`.env` file)
- Neo4j connection via environment variables

## Naming Conventions

- Python modules: `snake_case`
- Classes: `PascalCase`
- Functions/variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Config files: `snake_case.yaml`
- Data files: `snake_case.jsonl`
