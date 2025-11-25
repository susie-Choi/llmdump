"""Version information for LLMDump."""

# Version is managed in pyproject.toml
# This file imports it for backward compatibility
try:
    from importlib.metadata import version
    __version__ = version("llmdump")
except Exception:
    # Fallback for development
    __version__ = "0.2.0"

__title__ = "llmdump"
__description__ = "LLM-powered zero-day vulnerability prediction system"
__author__ = "Susie Choi"
__license__ = "MIT"
