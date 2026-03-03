from typing import List, Dict
from pathlib import Path
import json

class ReportManager:
    """Manage report generation and formatting"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.templates_dir = config.get('templates_dir', 'reports/templates')
        
    def generate_markdown(self, findings: List[Dict], output_path: str):
        """Generate markdown report"""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write("# Security Assessment Report\n\n")
            
            for finding in findings:
                f.write(f"## {finding.get('title')}\n\n")
                f.write(f"**Severity:** {finding.get('severity')}\n\n")
                f.write(f"{finding.get('description')}\n\n")
                f.write("---\n\n")
                
    def generate_json(self, findings: List[Dict], output_path: str):
        """Generate JSON report"""
        with open(output_path, 'w') as f:
            json.dump(findings, f, indent=2, default=str)
