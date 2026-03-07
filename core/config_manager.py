"""
config_manager.py  –  Zero-dependency config loader.
Uses the bundled _yaml_lite parser instead of PyYAML.

FIX: path resolution is now robust — works whether raptor.py is called
from ~/raptor, ~/raptor/core, or any other working directory.
"""

import os
import sys

# ── Always add both the project root AND core/ to sys.path ─────────────────
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))   # core/ directory
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)                  # ~/raptor

for _p in [_THIS_DIR, _PROJECT_ROOT]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _yaml_lite import safe_load as yaml_load
from typing import Dict, Any, Optional


class ConfigManager:
    """Manage configuration loading and validation."""

    def __init__(self, config_path: str):
        self.config_path = self._resolve_path(config_path)
        self.config      = self._load()

    def _resolve_path(self, path: str) -> str:
        """Try to find the config file relative to cwd or project root."""
        if os.path.isabs(path):
            return path
        # Try as-is (relative to cwd)
        if os.path.exists(path):
            return os.path.abspath(path)
        # Try relative to project root
        candidate = os.path.join(_PROJECT_ROOT, path)
        if os.path.exists(candidate):
            return candidate
        # Return original (will produce a helpful FileNotFoundError if missing)
        return path

    def _load(self) -> Dict:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml_load(f.read()) or {}
        except FileNotFoundError:
            print(f"[!] Config file not found: {self.config_path} — using defaults")
            return {}
        except Exception as e:
            print(f"[!] Error loading config: {e} — using defaults")
            return {}

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot-notation key.
        e.g.  config.get('database.path')
              config.get('modules.brute_force.max_attempts', 50)
        """
        keys  = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value if value is not None else default
