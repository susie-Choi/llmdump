"""
LLMDump - LLM-powered Zero-Day Vulnerability Prediction

A research framework for predicting zero-day vulnerabilities using
behavioral signals, clustering, and temporal analysis.

Architecture:
    - Spokes: Data collection from multiple sources
    - Hub: Central Neo4j graph database integration
    - Wheel: Clustering and pattern discovery
    - Oracle: Prediction and risk assessment
    - Axle: Evaluation and validation
"""

from .__version__ import __version__

__all__ = ['__version__']
