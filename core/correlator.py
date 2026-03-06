"""
config_manager.py  –  Zero-dependency config loader.
Uses the bundled _yaml_lite parser instead of PyYAML.
"""

import os
import sys

# Allow running from project root or from core/
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _yaml_lite import safe_load as yaml_load
from typing import Dict


class ConfigManager:
    """Manage configuration loading and validation."""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load()

    def _load(self) -> Dict:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml_load(f.read()) or {}
        except FileNotFoundError:
            return {}

    def get(self, key: str, default=None):
        """Get configuration value using dot-notation key."""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value
