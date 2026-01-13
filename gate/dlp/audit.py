"""
DLP Audit Logger
บันทึก audit log ของการตรวจจับข้อมูลละเอียดอ่อน
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class AuditEntry:
    """รายการ audit log"""
    timestamp: str
    pattern_type: str
    severity: str
    action: str
    matched_text_preview: str  # First 50 chars only for security
    confidence: float
    source: str = "unknown"
    user: str = "system"


class DLPAuditLogger:
    """บันทึกและจัดการ audit logs"""
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize audit logger
        
        Args:
            db_path: Path to SQLite database file
        """
        if db_path is None:
            db_path = Path.home() / ".kagent_dlp_audit.db"
        
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS dlp_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    matched_text_preview TEXT,
                    confidence REAL,
                    source TEXT,
                    user TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better query performance
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON dlp_audit_log(timestamp)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_pattern_type 
                ON dlp_audit_log(pattern_type)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_severity 
                ON dlp_audit_log(severity)
            """)
            
            conn.commit()
    
    def log(self, 
            pattern_type: str,
            severity: str,
            action: str,
            matched_text: str,
            confidence: float,
            source: str = "gate_controller",
            user: str = "system") -> int:
        """
        Log a DLP detection event
        
        Args:
            pattern_type: Type of pattern detected
            severity: Severity level
            action: Action taken
            matched_text: The matched sensitive text
            confidence: Detection confidence score
            source: Source of the detection
            user: User associated with the event
            
        Returns:
            ID of the inserted log entry
        """
        timestamp = datetime.now().isoformat()
        
        # Only store first 50 chars for security (preview only)
        preview = matched_text[:50] if len(matched_text) > 50 else matched_text
        
        entry = AuditEntry(
            timestamp=timestamp,
            pattern_type=pattern_type,
            severity=severity,
            action=action,
            matched_text_preview=preview,
            confidence=confidence,
            source=source,
            user=user
        )
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO dlp_audit_log 
                (timestamp, pattern_type, severity, action, matched_text_preview, 
                 confidence, source, user)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.timestamp,
                entry.pattern_type,
                entry.severity,
                entry.action,
                entry.matched_text_preview,
                entry.confidence,
                entry.source,
                entry.user
            ))
            conn.commit()
            return cursor.lastrowid
    
    def query_logs(self,
                   pattern_type: Optional[str] = None,
                   severity: Optional[str] = None,
                   action: Optional[str] = None,
                   limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query audit logs
        
        Args:
            pattern_type: Filter by pattern type
            severity: Filter by severity
            action: Filter by action
            limit: Maximum number of records to return
            
        Returns:
            List of audit log entries
        """
        query = "SELECT * FROM dlp_audit_log WHERE 1=1"
        params = []
        
        if pattern_type:
            query += " AND pattern_type = ?"
            params.append(pattern_type)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if action:
            query += " AND action = ?"
            params.append(action)
        
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get audit log statistics
        
        Returns:
            Dictionary with statistics
        """
        with sqlite3.connect(self.db_path) as conn:
            # Total detections
            total = conn.execute(
                "SELECT COUNT(*) FROM dlp_audit_log"
            ).fetchone()[0]
            
            # By severity
            by_severity = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as count FROM dlp_audit_log GROUP BY severity"
            ):
                by_severity[row[0]] = row[1]
            
            # By action
            by_action = {}
            for row in conn.execute(
                "SELECT action, COUNT(*) as count FROM dlp_audit_log GROUP BY action"
            ):
                by_action[row[0]] = row[1]
            
            # Top pattern types
            top_patterns = []
            for row in conn.execute(
                """SELECT pattern_type, COUNT(*) as count 
                   FROM dlp_audit_log 
                   GROUP BY pattern_type 
                   ORDER BY count DESC 
                   LIMIT 10"""
            ):
                top_patterns.append({'pattern_type': row[0], 'count': row[1]})
            
            return {
                'total_detections': total,
                'by_severity': by_severity,
                'by_action': by_action,
                'top_patterns': top_patterns
            }
    
    def clear_old_logs(self, days: int = 90):
        """
        Clear audit logs older than specified days
        
        Args:
            days: Number of days to keep logs
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                DELETE FROM dlp_audit_log 
                WHERE created_at < datetime('now', '-' || ? || ' days')
            """, (days,))
            conn.commit()
