"""
DLP Scanner Module
ตรวจจับข้อมูลที่ละเอียดอ่อน (Sensitive Data Detection)
"""

import re
import math
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class Detection:
    """การตรวจพบข้อมูลละเอียดอ่อน"""
    pattern_type: str
    matched_text: str
    start_pos: int
    end_pos: int
    confidence: float


class DLPScanner:
    """สแกนและตรวจจับข้อมูลที่ละเอียดอ่อน"""
    
    # Regex patterns for sensitive data detection
    PATTERNS = {
        # API Keys & Tokens
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'aws_secret[_]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
        'github_token': r'gh[pousr]_[A-Za-z0-9]{36,}',
        'generic_api_key': r'(?i)(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})',
        'bearer_token': r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
        'jwt_token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        
        # Passwords
        'password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{6,})',
        
        # Personal Identifiable Information (PII)
        'thai_citizen_id': r'\b[0-9]{1}-?[0-9]{4}-?[0-9]{5}-?[0-9]{2}-?[0-9]{1}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone_thai': r'\b0[0-9]{1,2}-?[0-9]{3,4}-?[0-9]{4}\b',
        'phone_international': r'\+[0-9]{1,3}[- ]?[0-9]{1,4}[- ]?[0-9]{3,4}[- ]?[0-9]{4}',
        
        # Credit Cards (Luhn algorithm should be checked separately)
        'credit_card': r'\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b',
        
        # Private Keys
        'private_key_rsa': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        'private_key_openssh': r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
        'private_key_pgp': r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----',
        
        # Sensitive Paths
        'sensitive_path_etc': r'/etc/(passwd|shadow|sudoers|ssh/)',
        'sensitive_path_ssh': r'\.ssh/(id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pub)?',
        'sensitive_path_env': r'\.env(?:\.[a-z]+)?',
        'sensitive_path_config': r'(?:config|credentials)\.(?:json|yaml|yml|ini|conf)',
    }
    
    def __init__(self, custom_patterns: Dict[str, str] = None):
        """
        Initialize DLP Scanner
        
        Args:
            custom_patterns: Custom regex patterns to add {name: regex}
        """
        self.patterns = self.PATTERNS.copy()
        if custom_patterns:
            self.patterns.update(custom_patterns)
        
        # Compile regex patterns for performance
        self._compiled_patterns = {
            name: re.compile(pattern)
            for name, pattern in self.patterns.items()
        }
    
    def scan(self, text: str) -> List[Detection]:
        """
        Scan text for sensitive data
        
        Args:
            text: Text to scan
            
        Returns:
            List of Detection objects
        """
        detections = []
        
        # Pattern-based detection
        for pattern_type, compiled_pattern in self._compiled_patterns.items():
            for match in compiled_pattern.finditer(text):
                detection = Detection(
                    pattern_type=pattern_type,
                    matched_text=match.group(0),
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=self._calculate_confidence(pattern_type, match.group(0))
                )
                detections.append(detection)
        
        # Entropy-based detection for high-entropy strings
        entropy_detections = self._detect_high_entropy(text)
        detections.extend(entropy_detections)
        
        return detections
    
    def _calculate_confidence(self, pattern_type: str, matched_text: str) -> float:
        """
        Calculate confidence score for detection
        
        Args:
            pattern_type: Type of pattern matched
            matched_text: The matched text
            
        Returns:
            Confidence score (0.0 - 1.0)
        """
        # Base confidence by pattern type
        high_confidence_patterns = {
            'aws_access_key', 'github_token', 'private_key_rsa', 
            'private_key_openssh', 'private_key_pgp', 'jwt_token'
        }
        
        medium_confidence_patterns = {
            'thai_citizen_id', 'email', 'bearer_token'
        }
        
        if pattern_type in high_confidence_patterns:
            base_confidence = 0.95
        elif pattern_type in medium_confidence_patterns:
            base_confidence = 0.85
        else:
            base_confidence = 0.70
        
        # Adjust based on Thai Citizen ID validation
        if pattern_type == 'thai_citizen_id':
            if self._validate_thai_citizen_id(matched_text):
                return 0.98
            else:
                return 0.50
        
        # Adjust based on credit card Luhn validation
        if pattern_type == 'credit_card':
            if self._luhn_check(matched_text):
                return 0.95
            else:
                return 0.30
        
        return base_confidence
    
    def _validate_thai_citizen_id(self, id_number: str) -> bool:
        """
        Validate Thai citizen ID using checksum algorithm
        
        Args:
            id_number: Thai citizen ID (13 digits)
            
        Returns:
            True if valid, False otherwise
        """
        # Remove hyphens
        id_clean = id_number.replace('-', '')
        
        if len(id_clean) != 13 or not id_clean.isdigit():
            return False
        
        # Calculate checksum
        total = 0
        for i in range(12):
            total += int(id_clean[i]) * (13 - i)
        
        checksum = (11 - (total % 11)) % 10
        return checksum == int(id_clean[12])
    
    def _luhn_check(self, card_number: str) -> bool:
        """
        Validate credit card number using Luhn algorithm
        
        Args:
            card_number: Credit card number
            
        Returns:
            True if valid, False otherwise
        """
        # Remove spaces and hyphens
        card_clean = card_number.replace(' ', '').replace('-', '')
        
        if not card_clean.isdigit():
            return False
        
        # Luhn algorithm
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d * 2))
            return checksum % 10
        
        return luhn_checksum(card_clean) == 0
    
    def _detect_high_entropy(self, text: str, threshold: float = 4.5) -> List[Detection]:
        """
        Detect high-entropy strings that might be secrets
        
        Args:
            text: Text to analyze
            threshold: Entropy threshold (default: 4.5)
            
        Returns:
            List of Detection objects
        """
        detections = []
        
        # Find potential secret strings (alphanumeric sequences of 20+ chars)
        pattern = re.compile(r'\b[A-Za-z0-9+/=]{20,}\b')
        
        for match in pattern.finditer(text):
            matched_text = match.group(0)
            entropy = self._calculate_entropy(matched_text)
            
            if entropy >= threshold:
                detection = Detection(
                    pattern_type='high_entropy_string',
                    matched_text=matched_text,
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=min(entropy / 5.0, 0.95)  # Normalize to 0-0.95
                )
                detections.append(detection)
        
        return detections
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Args:
            text: String to calculate entropy for
            
        Returns:
            Entropy value
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        
        for count in frequencies.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def has_sensitive_data(self, text: str) -> bool:
        """
        Quick check if text contains sensitive data
        
        Args:
            text: Text to check
            
        Returns:
            True if sensitive data found, False otherwise
        """
        return len(self.scan(text)) > 0
