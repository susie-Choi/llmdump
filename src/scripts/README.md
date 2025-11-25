# LLMDump Scripts

Unified scripts for LLMDump data collection, loading, and system management.

---

## 🚀 Main Scripts

### `collect_data.py` - Data Collection
Unified script for collecting data from all sources.

**Usage**:
```bash
# Collect all data sources
python src/scripts/collect_data.py --all

# Collect specific sources
python src/scripts/collect_data.py --cve
python src/scripts/collect_data.py --epss
python src/scripts/collect_data.py --kev
python src/scripts/collect_data.py --commits --repository django/django
python src/scripts/collect_data.py --exploits
python src/scripts/collect_data.py --advisory

# Collect CVE data for date range
python src/scripts/collect_data.py --cve --start-date 2024-01-01 --end-date 2024-12-31

# Collect GitHub commits
python src/scripts/collect_data.py --commits --repository django/django --days-back 30
```

**Data Sources**:
- CVE data from NVD
- EPSS scores
- KEV catalog
- GitHub commits
- Exploit-DB data
- GitHub advisories

---

### `load_to_neo4j.py` - Neo4j Loading
Unified script for loading collected data into Neo4j.

**Usage**:
```bash
# Load all data sources
python src/scripts/load_to_neo4j.py --all

# Load specific sources
python src/scripts/load_to_neo4j.py --cve
python src/scripts/load_to_neo4j.py --epss
python src/scripts/load_to_neo4j.py --kev
python src/scripts/load_to_neo4j.py --commits
python src/scripts/load_to_neo4j.py --exploits
python src/scripts/load_to_neo4j.py --advisory

# Load with custom Neo4j connection
python src/scripts/load_to_neo4j.py --all --uri bolt://localhost:7687 --password mypassword
```

**Requirements**:
- Neo4j running (use `docker-compose up -d`)
- Data files in `data/input/` directory
- Environment variables set (NEO4J_URI, NEO4J_PASSWORD)

---

### `check_status.py` - System Status
Check LLMDump system status including data files, environment, and Neo4j.

**Usage**:
```bash
# Check full system status
python src/scripts/check_status.py

# Check only data files
python src/scripts/check_status.py --data-only

# Check only environment variables
python src/scripts/check_status.py --env-only

# Check only Neo4j
python src/scripts/check_status.py --neo4j-only
```

**Checks**:
- Data files existence and size
- Environment variables (GITHUB_TOKEN, GEMINI_API_KEY, NEO4J_*)
- Neo4j connection and data statistics

---

## 📋 Quick Start Workflow

### 1. Check System Status
```bash
python src/scripts/check_status.py
```

### 2. Collect Data
```bash
python src/scripts/collect_data.py --all
```

### 3. Load to Neo4j
```bash
python src/scripts/load_to_neo4j.py --all
```

### 4. Verify
```bash
python src/scripts/check_status.py --neo4j-only
```

---

## 🗂️ Additional Scripts

### `create_release.sh` / `create_release.ps1`
Create and publish a new release.

**Usage**:
```bash
# Linux/Mac
./src/scripts/create_release.sh 0.2.1

# Windows
.\src\scripts\create_release.ps1 0.2.1
```

### `collect_image_dataset.py`
Collect image dataset for multimodal research.

### `red_team_attacks.py`
Red team attack simulation scripts.

---

## 📁 Archive

Old scripts have been moved to `archive/` directory for reference:
- `archive/collection/` - Individual collection scripts
- `archive/loading/` - Individual loading scripts
- `archive/analysis/` - Analysis scripts
- `archive/paper/` - Paper-related scripts
- `archive/deployment/` - Deployment scripts

These are kept for backward compatibility and reference, but the unified scripts above should be used for new work.

---

## 🔧 Environment Variables

Required environment variables (set in `.env` file):

```bash
# GitHub API
GITHUB_TOKEN=your_github_token

# Gemini LLM
GEMINI_API_KEY=your_gemini_api_key

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password
```

---

## 📚 Documentation

- **User Guide**: [docs/GUIDE.md](../../docs/GUIDE.md)
- **Development Guide**: [docs/DEVELOPMENT.md](../../docs/DEVELOPMENT.md)
- **Research Plan**: [docs/RESEARCH.md](../../docs/RESEARCH.md)

---

## 🆘 Troubleshooting

### Data Collection Issues

**Problem**: GitHub rate limiting
```bash
# Solution: Set GITHUB_TOKEN in .env
GITHUB_TOKEN=your_token_here
```

**Problem**: No data collected
```bash
# Solution: Check date range or repository name
python src/scripts/collect_data.py --cve --start-date 2024-01-01 --end-date 2024-12-31
```

### Neo4j Loading Issues

**Problem**: Connection failed
```bash
# Solution: Check Neo4j is running
docker ps | grep neo4j

# Start Neo4j if not running
docker-compose up -d
```

**Problem**: Data file not found
```bash
# Solution: Collect data first
python src/scripts/collect_data.py --all
```

### Status Check Issues

**Problem**: Environment variables not set
```bash
# Solution: Create .env file
cat > .env << EOF
GITHUB_TOKEN=your_token
GEMINI_API_KEY=your_key
NEO4J_URI=bolt://localhost:7687
NEO4J_PASSWORD=your_password
EOF
```

---

**LLMDump v0.2.0** - Unified Scripts

*For detailed usage, see the documentation in `docs/`*
