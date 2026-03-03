import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional

class DatabaseManager:
    """Manages SQLite database for findings and assets"""
    
    def __init__(self, db_path: str = None):
        # Use /tmp if no path provided or if we can't write to the default location
        if db_path is None:
            db_path = "/tmp/raptor.db"
        
        # Try to use the provided path, fallback to /tmp if needed
        self.db_path = self._get_writable_path(db_path)
        print(f"[+] Database path: {self.db_path}")
        self._init_db()
        
    def _get_writable_path(self, preferred_path: str) -> str:
        """Get a writable path for the database"""
        preferred_path = os.path.abspath(preferred_path)
        db_dir = os.path.dirname(preferred_path)
        
        # Try to create the preferred directory
        try:
            if not os.path.exists(db_dir):
                os.makedirs(db_dir, mode=0o755, exist_ok=True)
            
            # Test if we can write there
            test_file = os.path.join(db_dir, ".write_test")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            
            return preferred_path
        except (OSError, IOError, PermissionError) as e:
            print(f"[!] Cannot write to {db_dir}: {e}")
            print(f"[!] Falling back to /tmp/raptor.db")
            return "/tmp/raptor.db"
        
    def _init_db(self):
        """Initialize database schema"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Findings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    poc TEXT,
                    remediation TEXT,
                    cvss_score REAL,
                    bounty_score INTEGER,
                    timestamp TEXT,
                    target TEXT,
                    status TEXT DEFAULT 'new'
                )
            ''')
            
            # Assets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT,
                    parent_id INTEGER,
                    metadata TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    FOREIGN KEY (parent_id) REFERENCES assets(id)
                )
            ''')
            
            # Attack paths table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    chain TEXT,
                    estimated_bounty INTEGER,
                    complexity TEXT,
                    status TEXT DEFAULT 'potential'
                )
            ''')
            
            conn.commit()
            conn.close()
            print("[+] Database initialized successfully")
            
        except Exception as e:
            print(f"[-] Database error: {e}")
            raise
        
    def save_finding(self, finding) -> int:
        """Save a finding to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO findings 
            (module, title, severity, description, evidence, poc, remediation, 
             cvss_score, bounty_score, timestamp, target)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.module,
            finding.title,
            finding.severity,
            finding.description,
            json.dumps(finding.evidence),
            finding.poc,
            finding.remediation,
            finding.cvss_score,
            finding.bounty_score,
            finding.timestamp.isoformat(),
            finding.target
        ))
        
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return finding_id
        
    def get_findings(self, module: Optional[str] = None, 
                    severity: Optional[str] = None) -> List[Dict]:
        """Retrieve findings with optional filtering"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        
        if module:
            query += " AND module = ?"
            params.append(module)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
            
        query += " ORDER BY cvss_score DESC, bounty_score DESC"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
        
    def save_asset(self, asset_type: str, value: str, source: str,
                   parent_id: Optional[int] = None, metadata: Dict = None) -> int:
        """Save an asset to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        
        cursor.execute(
            "SELECT id FROM assets WHERE type = ? AND value = ?",
            (asset_type, value)
        )
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute(
                "UPDATE assets SET last_seen = ? WHERE id = ?",
                (now, existing[0])
            )
            asset_id = existing[0]
        else:
            cursor.execute('''
                INSERT INTO assets (type, value, source, parent_id, metadata, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (asset_type, value, source, parent_id, json.dumps(metadata or {}), now, now))
            asset_id = cursor.lastrowid
            
        conn.commit()
        conn.close()
        return asset_id
        
    def get_assets(self, asset_type: Optional[str] = None) -> List[Dict]:
        """Retrieve assets"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if asset_type:
            cursor.execute("SELECT * FROM assets WHERE type = ?", (asset_type,))
        else:
            cursor.execute("SELECT * FROM assets")
            
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
        
    def save_attack_path(self, name: str, description: str, 
                        chain: List[int], estimated_bounty: int, 
                        complexity: str) -> int:
        """Save an attack path"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attack_paths (name, description, chain, estimated_bounty, complexity)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, description, json.dumps(chain), estimated_bounty, complexity))
        
        path_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return path_id
