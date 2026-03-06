"""
correlator.py  –  Zero-dependency attack-path correlator.
Replaces networkx with a simple adjacency-dict graph.
Public API (AttackPathCorrelator, .analyze()) is unchanged.
"""

from typing import List, Dict
from collections import defaultdict


class _DiGraph:
    """Minimal directed graph to replace networkx.DiGraph."""

    def __init__(self):
        self._nodes: dict = {}
        self._edges: list = []

    def add_node(self, node_id, **attrs):
        self._nodes[node_id] = attrs

    def add_edge(self, src, dst, **attrs):
        self._edges.append((src, dst, attrs))

    def nodes(self):
        return list(self._nodes.keys())

    def edges(self):
        return [(s, d) for s, d, _ in self._edges]


class AttackPathCorrelator:
    """Correlate findings into attack paths."""

    def __init__(self, db_manager, graph_manager=None):
        self.db    = db_manager
        self.graph = graph_manager
        self._g    = _DiGraph()   # internal lightweight graph

    def analyze(self, findings: List[Dict]) -> List[Dict]:
        """Analyse findings and identify attack chains."""
        attack_paths = []

        by_target = defaultdict(list)
        for f in findings:
            by_target[f.get('target')].append(f)

        for target, target_findings in by_target.items():
            recon    = [f for f in target_findings if f.get('module') == 'recon']
            misconfig = [f for f in target_findings if f.get('module') == 'server_misconfig']
            idor     = [f for f in target_findings if f.get('module') == 'idor']

            # Pattern 1: Recon → Misconfig → IDOR
            if recon and misconfig and idor:
                path = {
                    'name':             'Full Application Compromise',
                    'description':      'Staging environment found with misconfigurations '
                                        'allowing IDOR exploitation',
                    'chain':            [f.get('id') for f in recon + misconfig + idor],
                    'estimated_bounty': 5000,
                    'complexity':       'Medium',
                    'findings':         recon[:1] + misconfig[:1] + idor[:1],
                }
                attack_paths.append(path)
                # record in lightweight graph
                self._g.add_node('recon');    self._g.add_node('misconfig'); self._g.add_node('idor')
                self._g.add_edge('recon', 'misconfig'); self._g.add_edge('misconfig', 'idor')

            # Pattern 2: Missing headers + IDOR
            headers = [f for f in target_findings if 'Header' in f.get('title', '')]
            if headers and idor:
                path = {
                    'name':             'Session Hijacking to IDOR',
                    'description':      'Missing security headers combined with IDOR vulnerability',
                    'chain':            [],
                    'estimated_bounty': 3000,
                    'complexity':       'Low',
                    'findings':         headers[:1] + idor[:1],
                }
                attack_paths.append(path)

        # If graph_manager (Neo4j) is available, pull extra paths from it
        if self.graph and getattr(self.graph, 'enabled', False):
            try:
                graph_paths = self.graph.find_attack_paths()
                attack_paths.extend(graph_paths)
            except Exception:
                pass

        return attack_paths
