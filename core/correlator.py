from typing import List, Dict
import networkx as nx
from collections import defaultdict

class AttackPathCorrelator:
    """Correlate findings into attack paths"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.graph = nx.DiGraph()
        
    def analyze(self, findings: List[Dict]) -> List[Dict]:
        """Analyze findings and identify attack chains"""
        attack_paths = []
        
        # Group findings by target
        by_target = defaultdict(list)
        for f in findings:
            by_target[f.get('target')].append(f)
            
        # Look for common attack patterns
        for target, target_findings in by_target.items():
            # Pattern 1: Recon -> Misconfig -> Injection
            recon = [f for f in target_findings if f.get('module') == 'recon']
            misconfig = [f for f in target_findings if f.get('module') == 'server_misconfig']
            idor = [f for f in target_findings if f.get('module') == 'idor']
            
            if recon and misconfig and idor:
                path = {
                    'name': 'Full Application Compromise',
                    'description': f'Staging environment found with misconfigurations allowing IDOR exploitation',
                    'chain': [f.get('id') for f in recon + misconfig + idor],
                    'estimated_bounty': 5000,
                    'complexity': 'Medium',
                    'findings': recon[:1] + misconfig[:1] + idor[:1]
                }
                attack_paths.append(path)
                
            # Pattern 2: Missing headers + IDOR
            headers = [f for f in target_findings if 'Header' in f.get('title', '')]
            if headers and idor:
                path = {
                    'name': 'Session Hijacking to IDOR',
                    'description': 'Missing security headers combined with IDOR vulnerability',
                    'chain': [],
                    'estimated_bounty': 3000,
                    'complexity': 'Low',
                    'findings': headers[:1] + idor[:1]
                }
                attack_paths.append(path)
                
        return attack_paths
