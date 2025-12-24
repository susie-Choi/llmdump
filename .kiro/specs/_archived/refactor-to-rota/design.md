# ROTA Architecture Refactoring Design

## Overview

This document outlines the technical design for refactoring the `zero_day_defense` codebase into the ROTA (Rotating Threat Analysis) architecture. The design emphasizes simplicity, modularity, and research focus.

## Architecture Philosophy

The ROTA architecture uses a wheel metaphor:

```
                    ┌─────────────┐
                    │   ORACLE    │
                    │ (Prediction)│
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐        ┌────▼────┐       ┌────▼────┐
   │  WHEEL  │        │   HUB   │       │  AXLE   │
   │(Cluster)│◄───────┤ (Neo4j) │──────►│  (Eval) │
   └────▲────┘        └────▲────┘       └─────────┘
        │                  │
        └──────────────────┼──────────────────┘
                           │
                      ┌────▼────┐
                      │ SPOKES  │
                      │ (Data)  │
                      └─────────┘
```

- **Spokes**: Collect data from various sources (CVE, EPSS, KEV, etc.)
- **Hub**: Central integration point (Neo4j graph database)
- **Wheel**: Rotates to find patterns (clustering, analysis)
- **Oracle**: Predicts future threats (risk scoring)
- **Axle**: Supports the wheel (evaluation, validation)

## New Directory Structure

```
src/rota/
├── __init__.py                 # Main package init
├── __version__.py              # Version info
├── config.py                   # Configuration management
│
├── spokes/                     # Data Collection
│   ├── __init__.py
│   ├── base.py                 # Base collector class
│   ├── cve.py                  # CVE/NVD collector
│   ├── epss.py                 # EPSS collector
│   ├── advisory.py             # GitHub Advisory
│   ├── exploit_db.py           # Exploit-DB
│   ├── kev.py                  # CISA KEV (new)
│   └── github.py               # GitHub metadata
│
├── hub/                        # Data Integration
│   ├── __init__.py
│   ├── connection.py           # Neo4j connection management
│   ├── loader.py               # Data loading utilities
│   ├── schema.py               # Graph schema management
│   └── queries.py              # Common graph queries
│
├── wheel/                      # Clustering & Patterns
│   ├── __init__.py
│   ├── clusterer.py            # Clustering algorithms
│   ├── features.py             # Feature extraction
│   ├── patterns.py             # Pattern discovery
│   └── visualizer.py           # Cluster visualization
│
├── oracle/                     # Prediction
│   ├── __init__.py
│   ├── predictor.py            # Main prediction engine
│   ├── scorer.py               # Risk scoring
│   ├── models.py               # Data models
│   └── agents.py               # LLM agents (optional)
│
├── axle/                       # Evaluation
│   ├── __init__.py
│   ├── metrics.py              # Evaluation metrics
│   ├── validator.py            # Temporal validation
│   ├── baselines.py            # Baseline comparisons
│   └── statistics.py           # Statistical analysis
│
├── cli/                        # Command Line Interface
│   ├── __init__.py
│   ├── main.py                 # Main CLI entry point
│   ├── spokes_cmd.py           # Data collection commands
│   ├── hub_cmd.py              # Hub management commands
│   ├── wheel_cmd.py            # Clustering commands
│   ├── oracle_cmd.py           # Prediction commands
│   └── axle_cmd.py             # Evaluation commands
│
└── utils/                      # Utilities
    ├── __init__.py
    ├── logging.py              # Logging configuration
    ├── dates.py                # Date utilities
    └── io.py                   # File I/O utilities
```

## Module Designs

### 1. Spokes Module (Data Collection)

**Base Collector Interface**:
```python
# src/rota/spokes/base.py
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

class BaseCollector(ABC):
    """Base class for all data collectors."""
    
    def __init__(self, output_dir: str = "data/raw"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    @abstractmethod
    def collect(self, **kwargs) -> Dict[str, Any]:
        """
        Collect data from source.
        
        Returns:
            Statistics about collection (count, errors, etc.)
        """
        pass
    
    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate collected data."""
        pass
    
    def save_jsonl(self, data: List[Dict], filename: str) -> Path:
        """Save data in JSONL format."""
        pass
```

**Example Collector**:
```python
# src/rota/spokes/cve.py
from .base import BaseCollector

class CVECollector(BaseCollector):
    """Collector for CVE data from NVD."""
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def collect(self, start_date: str = None, end_date: str = None) -> Dict[str, Any]:
        """Collect CVE data from NVD API."""
        # Implementation
        pass
```

### 2. Hub Module (Data Integration)

**Connection Management**:
```python
# src/rota/hub/connection.py
from neo4j import GraphDatabase
from typing import Optional
import os

class Neo4jConnection:
    """Manages Neo4j database connections."""
    
    def __init__(self, uri: str = None, user: str = None, password: str = None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        self.driver = None
    
    def connect(self):
        """Establish connection to Neo4j."""
        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(self.user, self.password)
        )
    
    def close(self):
        """Close connection."""
        if self.driver:
            self.driver.close()
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
```

**Data Loader**:
```python
# src/rota/hub/loader.py
from pathlib import Path
from typing import Dict, Any
from .connection import Neo4jConnection

class DataLoader:
    """Loads data from spokes into Neo4j hub."""
    
    def __init__(self, connection: Neo4jConnection):
        self.conn = connection
    
    def load_cve_data(self, jsonl_path: Path) -> Dict[str, int]:
        """Load CVE data into Neo4j."""
        pass
    
    def load_epss_data(self, jsonl_path: Path) -> Dict[str, int]:
        """Load EPSS data into Neo4j."""
        pass
    
    def load_kev_data(self, jsonl_path: Path) -> Dict[str, int]:
        """Load KEV data into Neo4j."""
        pass
```

### 3. Wheel Module (Clustering)

**Clusterer**:
```python
# src/rota/wheel/clusterer.py
from typing import List, Dict, Any
import numpy as np
from sklearn.cluster import DBSCAN

class VulnerabilityClusterer:
    """Clusters vulnerabilities by patterns."""
    
    def __init__(self, method: str = "dbscan"):
        self.method = method
        self.model = None
    
    def fit(self, features: np.ndarray) -> 'VulnerabilityClusterer':
        """Fit clustering model."""
        if self.method == "dbscan":
            self.model = DBSCAN(eps=0.3, min_samples=5)
            self.model.fit(features)
        return self
    
    def predict(self, features: np.ndarray) -> np.ndarray:
        """Predict cluster labels."""
        return self.model.labels_
    
    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get clustering statistics."""
        pass
```

**Feature Extraction**:
```python
# src/rota/wheel/features.py
from typing import Dict, Any, List
import numpy as np

class FeatureExtractor:
    """Extracts features for clustering."""
    
    def extract_cve_features(self, cve_data: Dict[str, Any]) -> np.ndarray:
        """Extract features from CVE data."""
        features = []
        # CVSS score
        features.append(cve_data.get('cvss_score', 0))
        # CWE encoding
        features.extend(self._encode_cwe(cve_data.get('cwe_id')))
        # EPSS score
        features.append(cve_data.get('epss_score', 0))
        # KEV flag
        features.append(1 if cve_data.get('is_kev') else 0)
        return np.array(features)
    
    def _encode_cwe(self, cwe_id: str) -> List[float]:
        """Encode CWE ID as features."""
        pass
```

### 4. Oracle Module (Prediction)

**Predictor**:
```python
# src/rota/oracle/predictor.py
from typing import Dict, Any, List
from .scorer import RiskScorer

class VulnerabilityPredictor:
    """Predicts vulnerability exploitation risk."""
    
    def __init__(self):
        self.scorer = RiskScorer()
    
    def predict(self, cve_id: str) -> Dict[str, Any]:
        """
        Predict exploitation risk for a CVE.
        
        Returns:
            {
                'cve_id': str,
                'risk_score': float,
                'confidence': float,
                'factors': Dict[str, float],
                'recommendation': str
            }
        """
        pass
    
    def predict_batch(self, cve_ids: List[str]) -> List[Dict[str, Any]]:
        """Predict risk for multiple CVEs."""
        pass
```

**Risk Scorer**:
```python
# src/rota/oracle/scorer.py
from typing import Dict, Any

class RiskScorer:
    """Calculates risk scores for vulnerabilities."""
    
    def calculate_risk(self, features: Dict[str, Any]) -> float:
        """
        Calculate risk score from features.
        
        Factors:
        - CVSS score (0-10)
        - EPSS score (0-1)
        - KEV status (boolean)
        - Exploit availability (boolean)
        - Time since disclosure (days)
        """
        score = 0.0
        
        # CVSS contribution (40%)
        score += features.get('cvss_score', 0) * 0.04
        
        # EPSS contribution (30%)
        score += features.get('epss_score', 0) * 0.3
        
        # KEV contribution (20%)
        if features.get('is_kev'):
            score += 0.2
        
        # Exploit availability (10%)
        if features.get('has_exploit'):
            score += 0.1
        
        return min(score, 1.0)
```

### 5. Axle Module (Evaluation)

**Validator**:
```python
# src/rota/axle/validator.py
from typing import List, Dict, Any
from datetime import datetime

class TemporalValidator:
    """Validates predictions with temporal awareness."""
    
    def __init__(self, cutoff_date: datetime):
        self.cutoff_date = cutoff_date
    
    def validate(self, predictions: List[Dict], ground_truth: List[Dict]) -> Dict[str, float]:
        """
        Validate predictions against ground truth.
        
        Returns:
            {
                'precision': float,
                'recall': float,
                'f1': float,
                'lead_time_days': float
            }
        """
        pass
    
    def prevent_data_leakage(self, data: Dict[str, Any]) -> bool:
        """Check if data respects temporal cutoff."""
        pass
```

## CLI Design

**Main CLI Structure**:
```python
# src/rota/cli/main.py
import click

@click.group()
@click.version_option()
def cli():
    """ROTA - Rotating Threat Analysis"""
    pass

@cli.group()
def spokes():
    """Data collection commands"""
    pass

@cli.group()
def hub():
    """Data integration commands"""
    pass

@cli.group()
def wheel():
    """Clustering and pattern analysis"""
    pass

@cli.group()
def oracle():
    """Prediction and risk scoring"""
    pass

@cli.group()
def axle():
    """Evaluation and validation"""
    pass
```

**Example Commands**:
```bash
# Data collection
rota spokes collect cve --start-date 2024-01-01
rota spokes collect epss
rota spokes collect kev

# Data loading
rota hub load cve data/raw/cve/
rota hub load epss data/raw/epss/
rota hub status

# Clustering
rota wheel cluster --method dbscan
rota wheel patterns --min-support 0.1

# Prediction
rota oracle predict CVE-2024-1234
rota oracle scan --project django

# Evaluation
rota axle validate --cutoff-date 2024-01-01
rota axle compare-baselines
```

## Migration Strategy

### Phase 1: Create New Structure
1. Create `src/rota/` directory
2. Create all module directories (spokes, hub, wheel, oracle, axle)
3. Create `__init__.py` files
4. Update `pyproject.toml`

### Phase 2: Migrate Spokes
1. Copy `data_sources/` to `spokes/`
2. Create `base.py` with BaseCollector
3. Update each collector to inherit from BaseCollector
4. Add KEV collector

### Phase 3: Migrate Hub
1. Extract Neo4j code from scripts
2. Create connection management
3. Create loader utilities
4. Create schema management

### Phase 4: Migrate Wheel
1. Copy clustering code from `prediction/engine/`
2. Create feature extraction
3. Add pattern discovery
4. Add visualization

### Phase 5: Migrate Oracle
1. Copy prediction code from `prediction/`
2. Simplify prediction logic
3. Create risk scorer
4. Add prediction API

### Phase 6: Migrate Axle
1. Copy evaluation code from `evaluation/`
2. Create temporal validator
3. Add metrics calculation
4. Add baseline comparisons

### Phase 7: Update CLI
1. Create new CLI structure
2. Migrate commands
3. Add deprecation warnings
4. Update documentation

### Phase 8: Backward Compatibility
1. Create compatibility shims in `zero_day_defense/`
2. Add deprecation warnings
3. Update imports
4. Test compatibility

## Documentation Structure

```
docs/
├── README.md                   # Main documentation hub
├── architecture.md             # ROTA architecture overview
├── getting-started.md          # Quick start guide
├── modules/                    # Module documentation
│   ├── spokes.md
│   ├── hub.md
│   ├── wheel.md
│   ├── oracle.md
│   └── axle.md
├── guides/                     # How-to guides
│   ├── data-collection.md
│   ├── clustering.md
│   ├── prediction.md
│   └── evaluation.md
├── api/                        # API reference
│   └── (auto-generated)
├── research/                   # Research documentation
│   ├── directions.md
│   └── experiments.md
└── archive/                    # Old documentation
    ├── WORK_SUMMARY.md
    ├── TODAY_ACHIEVEMENTS.md
    └── ...
```

## Testing Strategy

### Unit Tests
```python
# tests/test_spokes/test_cve_collector.py
def test_cve_collector_initialization():
    collector = CVECollector()
    assert collector.output_dir.exists()

def test_cve_collector_validation():
    collector = CVECollector()
    valid_data = {'cve_id': 'CVE-2024-1234', ...}
    assert collector.validate(valid_data)
```

### Integration Tests
```python
# tests/integration/test_pipeline.py
def test_end_to_end_pipeline():
    # Collect data
    cve_collector = CVECollector()
    cve_collector.collect()
    
    # Load to hub
    with Neo4jConnection() as conn:
        loader = DataLoader(conn)
        loader.load_cve_data(...)
    
    # Cluster
    clusterer = VulnerabilityClusterer()
    clusterer.fit(...)
    
    # Predict
    predictor = VulnerabilityPredictor()
    result = predictor.predict('CVE-2024-1234')
    
    assert result['risk_score'] > 0
```

## Performance Considerations

- **Lazy Loading**: Import modules only when needed
- **Connection Pooling**: Reuse Neo4j connections
- **Batch Processing**: Process data in batches
- **Caching**: Cache frequently accessed data
- **Async Operations**: Use async for I/O operations where beneficial

## Security Considerations

- **API Keys**: Store in environment variables
- **Input Validation**: Validate all user inputs
- **SQL Injection**: Use parameterized Cypher queries
- **Rate Limiting**: Respect API rate limits
- **Error Handling**: Don't expose sensitive information in errors

## Future Enhancements

1. **Plugin System**: Allow custom collectors and predictors
2. **Web Dashboard**: Interactive visualization
3. **Real-time Monitoring**: Stream processing for new CVEs
4. **ML Models**: Advanced machine learning models
5. **Multi-language Support**: Support for multiple programming languages
