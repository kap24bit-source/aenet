"""
DLP Policy Engine
จัดการนโยบายความปลอดภัยและการดำเนินการ
"""

import json
from enum import Enum
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass


class Severity(Enum):
    """ระดับความรุนแรง"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Action(Enum):
    """การดำเนินการเมื่อพบข้อมูลละเอียดอ่อน"""
    LOG = "LOG"           # บันทึกเท่านั้น
    WARN = "WARN"         # เตือน + บันทึก
    BLOCK = "BLOCK"       # บล็อกการประมวลผล
    QUARANTINE = "QUARANTINE"  # กักกันข้อมูล


@dataclass
class PolicyRule:
    """กฎนโยบาย DLP"""
    pattern_type: str
    severity: Severity
    action: Action
    description: str = ""


class DLPPolicy:
    """จัดการนโยบาย DLP"""
    
    # Default policy rules
    DEFAULT_RULES = {
        # Critical severity - BLOCK
        'aws_access_key': PolicyRule('aws_access_key', Severity.CRITICAL, Action.BLOCK, 'AWS Access Key detected'),
        'aws_secret_key': PolicyRule('aws_secret_key', Severity.CRITICAL, Action.BLOCK, 'AWS Secret Key detected'),
        'private_key_rsa': PolicyRule('private_key_rsa', Severity.CRITICAL, Action.BLOCK, 'RSA Private Key detected'),
        'private_key_openssh': PolicyRule('private_key_openssh', Severity.CRITICAL, Action.BLOCK, 'OpenSSH Private Key detected'),
        'private_key_pgp': PolicyRule('private_key_pgp', Severity.CRITICAL, Action.BLOCK, 'PGP Private Key detected'),
        
        # High severity - QUARANTINE
        'github_token': PolicyRule('github_token', Severity.HIGH, Action.QUARANTINE, 'GitHub Token detected'),
        'generic_api_key': PolicyRule('generic_api_key', Severity.HIGH, Action.QUARANTINE, 'Generic API Key detected'),
        'password': PolicyRule('password', Severity.HIGH, Action.QUARANTINE, 'Password detected'),
        'jwt_token': PolicyRule('jwt_token', Severity.HIGH, Action.QUARANTINE, 'JWT Token detected'),
        'bearer_token': PolicyRule('bearer_token', Severity.HIGH, Action.QUARANTINE, 'Bearer Token detected'),
        
        # Medium severity - WARN
        'thai_citizen_id': PolicyRule('thai_citizen_id', Severity.MEDIUM, Action.WARN, 'Thai Citizen ID detected'),
        'credit_card': PolicyRule('credit_card', Severity.MEDIUM, Action.WARN, 'Credit Card Number detected'),
        'sensitive_path_etc': PolicyRule('sensitive_path_etc', Severity.MEDIUM, Action.WARN, 'Sensitive system path detected'),
        'sensitive_path_ssh': PolicyRule('sensitive_path_ssh', Severity.MEDIUM, Action.WARN, 'SSH key path detected'),
        
        # Low severity - LOG
        'email': PolicyRule('email', Severity.LOW, Action.LOG, 'Email address detected'),
        'phone_thai': PolicyRule('phone_thai', Severity.LOW, Action.LOG, 'Thai phone number detected'),
        'phone_international': PolicyRule('phone_international', Severity.LOW, Action.LOG, 'International phone number detected'),
        'sensitive_path_env': PolicyRule('sensitive_path_env', Severity.LOW, Action.LOG, 'Environment file path detected'),
        'sensitive_path_config': PolicyRule('sensitive_path_config', Severity.LOW, Action.LOG, 'Configuration file path detected'),
        'high_entropy_string': PolicyRule('high_entropy_string', Severity.MEDIUM, Action.WARN, 'High entropy string (possible secret)'),
    }
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize DLP Policy
        
        Args:
            config_path: Path to policy configuration file (JSON)
        """
        self.rules: Dict[str, PolicyRule] = self.DEFAULT_RULES.copy()
        self.enabled = True
        self.quarantine_path = Path.home() / ".kagent_dlp_quarantine"
        
        # Load custom configuration if provided
        if config_path and config_path.exists():
            self._load_config(config_path)
        
        # Ensure quarantine directory exists
        if not self.quarantine_path.exists():
            self.quarantine_path.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self, config_path: Path):
        """
        Load policy configuration from JSON file
        
        Args:
            config_path: Path to configuration file
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Update enabled flag
            self.enabled = config.get('enabled', True)
            
            # Update quarantine path
            if 'quarantine_path' in config:
                self.quarantine_path = Path(config['quarantine_path'])
            
            # Load custom severity actions
            if 'severity_actions' in config:
                self._apply_severity_actions(config['severity_actions'])
            
            # Load custom patterns
            if 'patterns' in config:
                self._load_custom_patterns(config['patterns'])
                
        except Exception as e:
            print(f"Warning: Failed to load DLP config from {config_path}: {e}")
    
    def _apply_severity_actions(self, severity_actions: Dict[str, str]):
        """
        Apply custom severity-action mappings
        
        Args:
            severity_actions: Dict mapping severity to action
        """
        severity_map = {
            'LOW': Severity.LOW,
            'MEDIUM': Severity.MEDIUM,
            'HIGH': Severity.HIGH,
            'CRITICAL': Severity.CRITICAL
        }
        
        action_map = {
            'LOG': Action.LOG,
            'WARN': Action.WARN,
            'BLOCK': Action.BLOCK,
            'QUARANTINE': Action.QUARANTINE
        }
        
        # Update rules based on severity actions
        # Create new PolicyRule objects to avoid mutating shared objects
        for pattern_type, rule in list(self.rules.items()):
            severity_str = rule.severity.value
            if severity_str in severity_actions:
                action_str = severity_actions[severity_str]
                if action_str in action_map:
                    # Create a new PolicyRule with the updated action
                    self.rules[pattern_type] = PolicyRule(
                        pattern_type=rule.pattern_type,
                        severity=rule.severity,
                        action=action_map[action_str],
                        description=rule.description
                    )
    
    def _load_custom_patterns(self, patterns: List[Dict]):
        """
        Load custom pattern rules
        
        Args:
            patterns: List of pattern rule definitions
        """
        for pattern_def in patterns:
            pattern_type = pattern_def.get('type')
            severity_str = pattern_def.get('severity', 'MEDIUM')
            action_str = pattern_def.get('action', 'WARN')
            description = pattern_def.get('description', '')
            
            if pattern_type:
                try:
                    severity = Severity[severity_str]
                    action = Action[action_str]
                    
                    self.rules[pattern_type] = PolicyRule(
                        pattern_type=pattern_type,
                        severity=severity,
                        action=action,
                        description=description
                    )
                except (KeyError, ValueError) as e:
                    print(f"Warning: Invalid pattern definition for {pattern_type}: {e}")
    
    def get_action(self, pattern_type: str) -> Action:
        """
        Get action for a pattern type
        
        Args:
            pattern_type: Type of pattern detected
            
        Returns:
            Action to take
        """
        if pattern_type in self.rules:
            return self.rules[pattern_type].action
        return Action.LOG  # Default action
    
    def get_severity(self, pattern_type: str) -> Severity:
        """
        Get severity for a pattern type
        
        Args:
            pattern_type: Type of pattern detected
            
        Returns:
            Severity level
        """
        if pattern_type in self.rules:
            return self.rules[pattern_type].severity
        return Severity.LOW  # Default severity
    
    def should_block(self, pattern_type: str) -> bool:
        """
        Check if pattern should block processing
        
        Args:
            pattern_type: Type of pattern detected
            
        Returns:
            True if should block, False otherwise
        """
        return self.get_action(pattern_type) == Action.BLOCK
    
    def should_quarantine(self, pattern_type: str) -> bool:
        """
        Check if pattern should be quarantined
        
        Args:
            pattern_type: Type of pattern detected
            
        Returns:
            True if should quarantine, False otherwise
        """
        return self.get_action(pattern_type) == Action.QUARANTINE
    
    def get_rule(self, pattern_type: str) -> Optional[PolicyRule]:
        """
        Get rule for a pattern type
        
        Args:
            pattern_type: Type of pattern
            
        Returns:
            PolicyRule or None
        """
        return self.rules.get(pattern_type)
