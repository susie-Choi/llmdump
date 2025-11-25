"""Configuration management for LLMDump."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import os
import yaml


@dataclass
class LLMDumpConfig:
    """Main LLMDump configuration."""
    
    # Data directories
    data_dir: Path = Path("data")
    raw_dir: Path = Path("data/raw")
    processed_dir: Path = Path("data/processed")
    
    # Neo4j configuration
    neo4j_uri: str = field(default_factory=lambda: os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    neo4j_user: str = field(default_factory=lambda: os.getenv("NEO4J_USER", "neo4j"))
    neo4j_password: str = field(default_factory=lambda: os.getenv("NEO4J_PASSWORD", ""))
    
    # API tokens
    github_token: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))
    nvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    
    # Collection settings
    cutoff_date: Optional[datetime] = None
    request_timeout: float = 30.0
    rate_limit_sleep: float = 1.0
    
    # Clustering settings
    clustering_method: str = "dbscan"
    min_cluster_size: int = 5
    
    # Prediction settings
    risk_threshold: float = 0.7
    confidence_threshold: float = 0.6
    
    def __post_init__(self):
        """Ensure directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_yaml(cls, path: Path) -> 'LLMDumpConfig':
        """Load configuration from YAML file."""
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        # Convert string paths to Path objects
        if 'data_dir' in data:
            data['data_dir'] = Path(data['data_dir'])
        if 'raw_dir' in data:
            data['raw_dir'] = Path(data['raw_dir'])
        if 'processed_dir' in data:
            data['processed_dir'] = Path(data['processed_dir'])
        
        # Convert cutoff_date string to datetime
        if 'cutoff_date' in data and isinstance(data['cutoff_date'], str):
            data['cutoff_date'] = datetime.fromisoformat(data['cutoff_date'])
        
        return cls(**data)
    
    def to_yaml(self, path: Path):
        """Save configuration to YAML file."""
        data = {
            'data_dir': str(self.data_dir),
            'raw_dir': str(self.raw_dir),
            'processed_dir': str(self.processed_dir),
            'neo4j_uri': self.neo4j_uri,
            'neo4j_user': self.neo4j_user,
            'request_timeout': self.request_timeout,
            'rate_limit_sleep': self.rate_limit_sleep,
            'clustering_method': self.clustering_method,
            'min_cluster_size': self.min_cluster_size,
            'risk_threshold': self.risk_threshold,
            'confidence_threshold': self.confidence_threshold,
        }
        
        if self.cutoff_date:
            data['cutoff_date'] = self.cutoff_date.isoformat()
        
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)


# Global config instance
_config: Optional[LLMDumpConfig] = None


def get_config() -> LLMDumpConfig:
    """Get global configuration instance."""
    global _config
    if _config is None:
        _config = LLMDumpConfig()
    return _config


def set_config(config: LLMDumpConfig):
    """Set global configuration instance."""
    global _config
    _config = config


def load_config(path: Path) -> LLMDumpConfig:
    """Load and set global configuration from file."""
    config = LLMDumpConfig.from_yaml(path)
    set_config(config)
    return config


__all__ = ['LLMDumpConfig', 'get_config', 'set_config', 'load_config']
