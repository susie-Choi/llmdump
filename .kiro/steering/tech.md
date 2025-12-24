---
inclusion: always
---

# Technology Stack

## Core Technologies

**Language**: Python 3.10+

**Package Management**:
- pip with requirements.txt
- setuptools with pyproject.toml

**Database**: Neo4j 5.0+ (graph database)

## Dependencies

### Core
- `pyyaml>=6.0` - Configuration parsing
- `requests>=2.31.0` - HTTP API calls
- `tqdm>=4.66.0` - Progress bars

### Visualization
- `matplotlib>=3.7.0` - Plotting
- `seaborn>=0.12.0` - Statistical visualization
- `scipy>=1.10.0` - Scientific computing
- `statsmodels>=0.14.0` - Statistical models

### Optional
- `neo4j>=5.0` - Neo4j driver (optional: neo4j extra)
- `py2neo>=2021.2` - Neo4j ORM (optional: neo4j extra)
- `streamlit>=1.28.0` - Dashboard (optional: dashboard extra)
- `plotly>=5.17.0` - Interactive plots (optional: dashboard extra)
- `pandas>=2.0.0` - Data analysis (optional: dashboard extra)

## Installation

### Basic Installation
```bash
pip install llmdump
```

### With Neo4j Support
```bash
pip install llmdump[neo4j]
```

### With Dashboard
```bash
pip install llmdump[dashboard]
```

### Development Installation
```bash
git clone https://github.com/susie-Choi/llmdump.git
cd llmdump
pip install -e .[dev,neo4j,dashboard]
```

## Environment Setup

Create `.env` file:
```bash
# GitHub API (for commit collection)
GITHUB_TOKEN=your_github_token

# Gemini API (for LLM code generation)
GEMINI_API_KEY=your_gemini_api_key

# Neo4j Database
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
```

## Common Commands

### Data Collection
```bash
# Collect all baseline data
python src/scripts/collect_data.py --all

# Collect specific sources
python src/scripts/collect_data.py --cve --start-date 2024-01-01
python src/scripts/collect_data.py --epss
python src/scripts/collect_data.py --kev
```

### Neo4j Operations
```bash
# Start Neo4j (Docker)
docker compose up -d

# Load data to Neo4j
python src/scripts/load_to_neo4j.py --all

# Check status
python src/scripts/check_status.py --neo4j-only
```

### Development
```bash
# Run tests
pytest

# Code formatting
black src/

# Type checking
mypy src/
```

## API Integrations

- **NVD API**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **EPSS API**: `https://api.first.org/data/v1/epss`
- **KEV Catalog**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **GitHub API**: `https://api.github.com`
- **Exploit-DB**: Web scraping with rate limiting

## Data Storage

**Input Data**: `data/input/*.jsonl`
- Consolidated, cleaned data ready for analysis

**Output Data**: `data/output/`
- Analysis results
- Predictions
- Reports

**Raw Data**: `data/raw/`
- Original API responses (for debugging)
