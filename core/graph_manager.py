#!/usr/bin/env python3
"""
RAPTOR Graph Database Manager 
===================================
Neo4j integration for graph-based vulnerability analysis and attack path discovery.
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import json
import asyncio

try:
    from neo4j import GraphDatabase, AsyncGraphDatabase
    from neo4j.exceptions import Neo4jError
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    print("[!] Neo4j driver not installed. Graph features disabled.")

@dataclass
class GraphNode:
    """Represents a node in the attack graph"""
    node_id: str
    node_type: str  # Target, Endpoint, Vulnerability, Credential, Resource
    properties: Dict[str, Any]
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class GraphEdge:
    """Represents a relationship between nodes"""
    edge_type: str  # HAS_ENDPOINT, HAS_VULNERABILITY, EXPLOITS, LEADS_TO, CAN_ACCESS
    source_id: str
    target_id: str
    properties: Dict[str, Any]

class GraphManager:
    """
    Manages Neo4j graph database for vulnerability correlation.
    
    Node Types:
    - Target: Root domain/IP
    - Endpoint: URLs/paths
    - Vulnerability: Discovered vulnerabilities
    - Credential: User sessions/credentials
    - Resource: Data objects (user IDs, files, etc.)
    
    Edge Types:
    - HAS_ENDPOINT: Target -> Endpoint
    - HAS_VULNERABILITY: Endpoint -> Vulnerability
    - EXPLOITS: Vulnerability -> Vulnerability (chaining)
    - LEADS_TO: Vulnerability -> Endpoint (post-exploitation)
    - CAN_ACCESS: Credential -> Resource
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = NEO4J_AVAILABLE and config.get('enabled', False)
        self.driver = None
        self.session = None
        
        if self.enabled:
            self._connect()
            
    def _connect(self):
        """Establish Neo4j connection with environment variable priority"""
        import os
        try:
            # Priority: 1. Env Vars, 2. Config (new style), 3. Config (README style), 4. Defaults
            uri = os.environ.get('NEO4J_URI') or self.config.get('neo4j_uri') or \
                  self.config.get('uri', 'bolt://localhost:7687')
            
            user = os.environ.get('NEO4J_USER') or self.config.get('neo4j_user') or \
                   self.config.get('username', 'neo4j')
            
            password = os.environ.get('NEO4J_PASSWORD') or self.config.get('neo4j_password') or \
                       self.config.get('password', 'password')
            
            # Support for bolt+s:// or neo4j+s:// if users have SSL-only setups
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.driver.verify_connectivity()
            print(f"[+] Neo4j connected: {uri}")
            self._init_schema()
        except Neo4jError as e:
            if "unauthorized" in str(e).lower():
                print(f"[-] Neo4j Auth Failed: Check NEO4J_PASSWORD environment variable or config.yaml")
            else:
                print(f"[-] Neo4j Error: {e}")
            self.enabled = False
        except Exception as e:
            print(f"[-] Neo4j connection failed: {e}")
            print(f"    Hint: Use 'export NEO4J_PASSWORD=your_pass' before running.")
            self.enabled = False
            
    def _init_schema(self):
        """Initialize graph schema with constraints and indexes"""
        constraints = [
            "CREATE CONSTRAINT target_id IF NOT EXISTS FOR (t:Target) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT cred_id IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
        ]
        
        indexes = [
            "CREATE INDEX target_domain IF NOT EXISTS FOR (t:Target) ON (t.domain)",
            "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
            "CREATE INDEX vuln_type IF NOT EXISTS FOR (v:Vulnerability) ON (v.vuln_type)",
        ]
        
        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Neo4jError as e:
                    if "already exists" not in str(e):
                        print(f"[!] Constraint error: {e}")
                        
            for index in indexes:
                try:
                    session.run(index)
                except Neo4jError as e:
                    if "already exists" not in str(e):
                        print(f"[!] Index error: {e}")
                        
    def add_target(self, domain: str, ip: Optional[str] = None, 
                   metadata: Dict = None) -> str:
        """Add a target node"""
        if not self.enabled:
            return None
            
        target_id = f"target_{domain.replace('.', '_')}"
        query = """
        MERGE (t:Target {id: $id})
        SET t.domain = $domain,
            t.ip = $ip,
            t.metadata = $metadata,
            t.discovered_at = datetime(),
            t.last_seen = datetime()
        RETURN t.id
        """
        
        with self.driver.session() as session:
            result = session.run(query, {
                'id': target_id,
                'domain': domain,
                'ip': ip,
                'metadata': json.dumps(metadata or {})
            })
            return result.single()[0]
            
    def add_endpoint(self, url: str, method: str = 'GET', 
                     target_id: Optional[str] = None,
                     parameters: List[str] = None,
                     status_code: int = None) -> str:
        """Add an endpoint node"""
        if not self.enabled:
            return None
            
        endpoint_id = f"ep_{hash(url + method) % 10000000}"
        query = """
        MERGE (e:Endpoint {id: $id})
        SET e.url = $url,
            e.method = $method,
            e.parameters = $parameters,
            e.status_code = $status_code,
            e.discovered_at = datetime()
        """
        
        params = {
            'id': endpoint_id,
            'url': url,
            'method': method,
            'parameters': json.dumps(parameters or []),
            'status_code': status_code
        }
        
        if target_id:
            query += """
            WITH e
            MATCH (t:Target {id: $target_id})
            MERGE (t)-[:HAS_ENDPOINT]->(e)
            """
            params['target_id'] = target_id
            
        with self.driver.session() as session:
            session.run(query, params)
            return endpoint_id
            
    def add_vulnerability(self, vuln_type: str, severity: str, 
                         endpoint_id: str, evidence: Dict,
                         cwe_id: Optional[str] = None,
                         cvss_score: float = 0.0,
                         bounty_score: int = 0) -> str:
        """Add a vulnerability node"""
        if not self.enabled:
            return None
            
        vuln_id = f"vuln_{hash(str(endpoint_id) + vuln_type) % 10000000}"
        query = """
        MATCH (e:Endpoint {id: $endpoint_id})
        MERGE (v:Vulnerability {id: $id})
        SET v.type = $vuln_type,
            v.severity = $severity,
            v.cwe_id = $cwe_id,
            v.cvss_score = $cvss_score,
            v.bounty_score = $bounty_score,
            v.evidence = $evidence,
            v.discovered_at = datetime(),
            v.status = 'open'
        MERGE (e)-[:HAS_VULNERABILITY]->(v)
        RETURN v.id
        """
        
        with self.driver.session() as session:
            result = session.run(query, {
                'id': vuln_id,
                'endpoint_id': endpoint_id,
                'vuln_type': vuln_type,
                'severity': severity,
                'cwe_id': cwe_id,
                'cvss_score': cvss_score,
                'bounty_score': bounty_score,
                'evidence': json.dumps(evidence)
            })
            return result.single()[0]
            
    def add_credential(self, username: str, session_token: Optional[str] = None,
                       role: str = 'user', target_id: Optional[str] = None) -> str:
        """Add a credential node"""
        if not self.enabled:
            return None
            
        cred_id = f"cred_{hash(username) % 10000000}"
        query = """
        MERGE (c:Credential {id: $id})
        SET c.username = $username,
            c.role = $role,
            c.session_token = $session_token,
            c.discovered_at = datetime()
        """
        
        params = {
            'id': cred_id,
            'username': username,
            'role': role,
            'session_token': session_token or 'unknown'
        }
        
        if target_id:
            query += """
            WITH c
            MATCH (t:Target {id: $target_id})
            MERGE (t)-[:HAS_CREDENTIAL]->(c)
            """
            params['target_id'] = target_id
            
        with self.driver.session() as session:
            session.run(query, params)
            return cred_id
            
    def add_resource(self, resource_type: str, resource_id: str,
                     owner: Optional[str] = None, endpoint_id: Optional[str] = None) -> str:
        """Add a resource node (for IDOR tracking)"""
        if not self.enabled:
            return None
            
        node_id = f"res_{resource_type}_{hash(resource_id) % 10000000}"
        query = """
        MERGE (r:Resource {id: $id})
        SET r.resource_type = $resource_type,
            r.resource_id = $resource_id,
            r.owner = $owner,
            r.discovered_at = datetime()
        """
        
        params = {
            'id': node_id,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'owner': owner or 'unknown'
        }
        
        if endpoint_id:
            query += """
            WITH r
            MATCH (e:Endpoint {id: $endpoint_id})
            MERGE (e)-[:EXPOSES]->(r)
            """
            params['endpoint_id'] = endpoint_id
            
        with self.driver.session() as session:
            session.run(query, params)
            return node_id
            
    def create_vulnerability_chain(self, source_vuln_id: str, 
                                   target_vuln_id: str,
                                   chain_type: str = "leads_to"):
        """Create relationship between vulnerabilities (exploit chaining)"""
        if not self.enabled:
            return
            
        query = """
        MATCH (v1:Vulnerability {id: $source_id})
        MATCH (v2:Vulnerability {id: $target_id})
        MERGE (v1)-[r:EXPLOITS {type: $chain_type, created_at: datetime()}]->(v2)
        """
        
        with self.driver.session() as session:
            session.run(query, {
                'source_id': source_vuln_id,
                'target_id': target_vuln_id,
                'chain_type': chain_type
            })
            
    def find_attack_paths(self, start_vuln_id: Optional[str] = None,
                         max_depth: int = 5) -> List[Dict]:
        """Find all possible attack paths from vulnerabilities"""
        if not self.enabled:
            return []
            
        if start_vuln_id:
            query = """
            MATCH path = (start:Vulnerability {id: $start_id})-[:EXPLOITS|LEADS_TO*1..$max_depth]->(end)
            WHERE start <> end
            RETURN [node in nodes(path) | node.id] as node_ids,
                   [node in nodes(path) | node.type] as node_types,
                   [rel in relationships(path) | type(rel)] as rel_types,
                   reduce(total = 0, v in nodes(path) | total + coalesce(v.bounty_score, 0)) as total_bounty
            ORDER BY total_bounty DESC
            LIMIT 20
            """
            params = {'start_id': start_vuln_id, 'max_depth': max_depth}
        else:
            query = """
            MATCH path = (v:Vulnerability)-[:EXPLOITS|LEADS_TO*1..$max_depth]->(end)
            WHERE v.status = 'open'
            RETURN [node in nodes(path) | node.id] as node_ids,
                   [node in nodes(path) | node.type] as node_types,
                   [rel in relationships(path) | type(rel)] as rel_types,
                   reduce(total = 0, n in nodes(path) | total + coalesce(n.bounty_score, 0)) as total_bounty
            ORDER BY total_bounty DESC
            LIMIT 20
            """
            params = {'max_depth': max_depth}
            
        with self.driver.session() as session:
            result = session.run(query, params)
            paths = []
            for record in result:
                paths.append({
                    'node_ids': record['node_ids'],
                    'node_types': record['node_types'],
                    'relationships': record['rel_types'],
                    'total_bounty': record['total_bounty'],
                    'path_length': len(record['node_ids'])
                })
            return paths
            
    def get_high_value_targets(self, min_cvss: float = 7.0) -> List[Dict]:
        """Find targets with high-value vulnerability chains"""
        if not self.enabled:
            return []
            
        query = """
        MATCH (t:Target)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE v.cvss_score >= $min_cvss
        RETURN t.domain as domain,
               count(v) as vuln_count,
               sum(v.bounty_score) as total_bounty,
               collect(DISTINCT v.type) as vuln_types
        ORDER BY total_bounty DESC
        """
        
        with self.driver.session() as session:
            result = session.run(query, {'min_cvss': min_cvss})
            return [dict(record) for record in result]
            
    def correlate_idor_access(self, credential_id: str) -> List[Dict]:
        """Find resources accessible by a credential (IDOR analysis)"""
        if not self.enabled:
            return []
            
        query = """
        MATCH (c:Credential {id: $cred_id})
        OPTIONAL MATCH (c)-[:CAN_ACCESS]->(r:Resource)
        OPTIONAL MATCH (r)<-[:EXPOSES]-(e:Endpoint)
        OPTIONAL MATCH (e)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN r.resource_type as resource_type,
               r.resource_id as resource_id,
               r.owner as owner,
               e.url as endpoint,
               v.type as vuln_type,
               v.severity as severity
        """
        
        with self.driver.session() as session:
            result = session.run(query, {'cred_id': credential_id})
            return [dict(record) for record in result]
            
    def sync_findings(self, target: str, findings: List[Dict]):
        """Sync a list of findings to the graph at once (for post-scan sync)"""
        if not self.enabled:
            return
            
        print(f"[*] Syncing {len(findings)} findings to Neo4j...")
        target_id = self.add_target(target.replace('https://', '').replace('http://', '').split('/')[0])
        
        for finding in findings:
            # 1. Add Endpoint
            url = finding.get('poc', target) if finding.get('poc') and finding.get('poc').startswith('http') else target
            ep_id = self.add_endpoint(url, target_id=target_id)
            
            # 2. Add Vulnerability
            self.add_vulnerability(
                vuln_type=finding.get('title', 'Unknown'),
                severity=finding.get('severity', 'Info'),
                endpoint_id=ep_id,
                evidence=finding.get('evidence', {}),
                cvss_score=finding.get('cvss_score', 0.0),
                bounty_score=finding.get('bounty_score', 0)
            )
        print(f"[+] Sync complete!")

    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
