"""GitHub Security Advisory collector for LLMDump."""

import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseCollector, CollectionError

logger = logging.getLogger(__name__)


class GitHubAdvisoryCollector(BaseCollector):
    """Collect security advisories from GitHub Advisory Database."""
    
    source_name = "github_advisory"
    BASE_URL = "https://api.github.com/advisories"
    
    def __init__(
        self,
        output_dir: str = "data/raw",
        github_token: Optional[str] = None,
        **kwargs
    ):
        super().__init__(output_dir=output_dir, **kwargs)
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        
        if self.github_token:
            self.session.headers.update({
                "Authorization": f"Bearer {self.github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            logger.info("Using GitHub token for advisory collection")
    
    def collect(self, **kwargs) -> Dict[str, Any]:
        """Collect advisories (not implemented for base collect)."""
        raise NotImplementedError("Use collect_bulk or collect_bulk_streaming")
    
    def validate(self, data: Dict[str, Any]) -> bool:
        """Validate advisory data."""
        required_fields = ["ghsa_id"]
        return all(field in data for field in required_fields)
    
    def collect_bulk_streaming(
        self,
        *,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        max_pages: Optional[int] = None,
    ):
        """Stream advisories with pagination.
        
        Args:
            ecosystem: Filter by ecosystem (npm, pip, maven, etc.)
            severity: Filter by severity (low, medium, high, critical)
            max_pages: Maximum number of pages to collect
        
        Yields:
            Individual advisory dictionaries
        """
        page = 1
        params = {"per_page": 100}
        
        if ecosystem:
            params["ecosystem"] = ecosystem
        if severity:
            params["severity"] = severity
        
        logger.info(f"Starting bulk streaming (ecosystem={ecosystem}, severity={severity})")
        
        while True:
            if max_pages and page > max_pages:
                logger.info(f"Reached max_pages limit: {max_pages}")
                break
            
            params["page"] = page
            
            try:
                response = self._request("GET", self.BASE_URL, params=params)
                advisories = response.json()
                
                if not advisories:
                    logger.info(f"No more results at page {page}")
                    break
                
                for advisory in advisories:
                    yield advisory
                
                logger.info(f"Page {page}: yielded {len(advisories)} advisories")
                
                # Check rate limits
                remaining = int(response.headers.get('X-RateLimit-Remaining', 999))
                if remaining < 5:
                    reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_time = max(reset_time - time.time(), 0) + 10
                    logger.warning(f"Rate limit low ({remaining}), waiting {wait_time:.0f}s")
                    time.sleep(wait_time)
                
                # Check pagination
                link_header = response.headers.get('Link', '')
                if 'rel="next"' not in link_header:
                    logger.info(f"No more pages (last page: {page})")
                    break
                
                page += 1
                time.sleep(self.rate_limit_sleep)
                
            except Exception as e:
                logger.error(f"Error on page {page}: {e}")
                break
        
        logger.info("Bulk streaming complete")


__all__ = ["GitHubAdvisoryCollector"]
