try:
    import yaml
except ModuleNotFoundError:
    raise ImportError("PyYAML required. Run: pip install pyyaml")

from typing import Dict
from typing import Dict

class ConfigManager:
    """Manage configuration loading and validation"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load()
        
    def _load(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {}
            
    def get(self, key: str, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value
