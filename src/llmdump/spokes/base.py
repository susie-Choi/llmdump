"""Base collector class for all data sources."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import logging
import time
import requests

logger = logging.getLogger(__name__)


class CollectionError(Exception):
    """Raised when data collection fails."""
    pass


class BaseCollector(ABC):
    """
    Base class for all LLMDump data collectors.
    
    Provides common functionality:
    - HTTP request handling with retry logic
    - JSONL file I/O
    - Data validation
    - Progress logging
    """
    
    source_name: str = "unknown"
    
    def __init__(
        self,
        output_dir: str = "data/raw",
        timeout: float = 30.0,
        rate_limit_sleep: float = 1.0,
        max_retries: int = 3,
        verify_ssl: bool = False,  # Disable SSL verification for corporate proxies
    ):
        """
        Initialize collector.
        
        Args:
            output_dir: Directory to save collected data
            timeout: HTTP request timeout in seconds
            rate_limit_sleep: Sleep duration when rate limited
            max_retries: Maximum number of retry attempts
            verify_ssl: Verify SSL certificates (default: False for corporate proxies)
        """
        self.output_dir = Path(output_dir) / self.source_name
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.timeout = timeout
        self.rate_limit_sleep = rate_limit_sleep
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'LLMDump-Research/0.2.0'
        })
    
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
        """
        Validate collected data.
        
        Args:
            data: Data to validate
            
        Returns:
            True if valid, False otherwise
        """
        pass
    
    def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        """
        Perform HTTP request with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object
            
        Raises:
            CollectionError: If request fails after retries
        """
        for attempt in range(self.max_retries):
            try:
                response = self.session.request(
                    method,
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    **kwargs
                )
                
                # Handle rate limiting
                if response.status_code == 429:
                    logger.warning(f"Rate limited, sleeping {self.rate_limit_sleep}s")
                    time.sleep(self.rate_limit_sleep)
                    continue
                
                # Check for success
                if response.ok:
                    return response
                
                # Log error and retry
                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{self.max_retries}): "
                    f"{response.status_code} {response.text[:200]}"
                )
                
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    
            except requests.RequestException as e:
                logger.warning(f"Request exception (attempt {attempt + 1}/{self.max_retries}): {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
        
        raise CollectionError(f"Failed to fetch {url} after {self.max_retries} attempts")
    
    def save_jsonl(
        self,
        data: List[Dict[str, Any]],
        filename: str,
        append: bool = False
    ) -> Path:
        """
        Save data in JSONL format.
        
        Args:
            data: List of dictionaries to save
            filename: Output filename
            append: If True, append to existing file
            
        Returns:
            Path to saved file
        """
        output_path = self.output_dir / filename
        mode = 'a' if append else 'w'
        
        with open(output_path, mode, encoding='utf-8') as f:
            for item in data:
                # Add metadata
                item['_collected_at'] = datetime.utcnow().isoformat()
                item['_source'] = self.source_name
                
                json.dump(item, f, ensure_ascii=False)
                f.write('\n')
        
        logger.info(f"Saved {len(data)} records to {output_path}")
        return output_path
    
    def load_jsonl(self, filename: str) -> List[Dict[str, Any]]:
        """
        Load data from JSONL file.
        
        Args:
            filename: Input filename
            
        Returns:
            List of dictionaries
        """
        input_path = self.output_dir / filename
        
        if not input_path.exists():
            logger.warning(f"File not found: {input_path}")
            return []
        
        data = []
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    data.append(json.loads(line))
        
        logger.info(f"Loaded {len(data)} records from {input_path}")
        return data
    
    def get_stats(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate collection statistics.
        
        Args:
            data: Collected data
            
        Returns:
            Statistics dictionary
        """
        return {
            'source': self.source_name,
            'total_records': len(data),
            'collected_at': datetime.utcnow().isoformat(),
            'output_dir': str(self.output_dir),
        }


__all__ = ['BaseCollector', 'CollectionError']
