import re
from typing import List
from gate.dlp.scanner import Detection


def sanitize(text: str) -> str:
    """
    Basic sanitization (legacy)
    """
    text = re.sub(r"/\S+", "[PATH]", text)
    text = re.sub(r"[A-Za-z0-9]{20,}", "[REDACTED]", text)
    return text


def redact_detections(text: str, detections: List[Detection]) -> str:
    """
    Redact sensitive data based on DLP detections
    
    Args:
        text: Original text
        detections: List of Detection objects from DLP scanner
        
    Returns:
        Text with sensitive data redacted
    """
    if not detections:
        return text
    
    # Sort detections by position (reverse order to maintain positions)
    sorted_detections = sorted(detections, key=lambda d: d.start_pos, reverse=True)
    
    result = text
    for detection in sorted_detections:
        # Choose redaction strategy based on pattern type
        redacted = _get_redaction(detection)
        result = result[:detection.start_pos] + redacted + result[detection.end_pos:]
    
    return result


def _get_redaction(detection: Detection) -> str:
    """
    Get appropriate redaction for a detection
    
    Args:
        detection: Detection object
        
    Returns:
        Redacted string
    """
    pattern_type = detection.pattern_type
    matched_text = detection.matched_text
    
    # Full redaction for critical secrets
    if pattern_type in ['aws_access_key', 'aws_secret_key', 'github_token', 
                        'generic_api_key', 'password', 'jwt_token', 'bearer_token',
                        'private_key_rsa', 'private_key_openssh', 'private_key_pgp']:
        return '[REDACTED_SECRET]'
    
    # Masked redaction for PII
    if pattern_type == 'credit_card':
        return _mask_credit_card(matched_text)
    
    if pattern_type == 'thai_citizen_id':
        return _mask_thai_id(matched_text)
    
    if pattern_type == 'email':
        return _mask_email(matched_text)
    
    if pattern_type in ['phone_thai', 'phone_international']:
        return _mask_phone(matched_text)
    
    # Default redaction
    return '[REDACTED]'


def _mask_credit_card(card: str) -> str:
    """
    Mask credit card number, showing only last 4 digits
    Example: 1234-5678-9012-3456 -> ****-****-****-3456
    """
    # Remove spaces and hyphens
    clean = card.replace(' ', '').replace('-', '')
    
    if len(clean) >= 4:
        return '*' * (len(clean) - 4) + clean[-4:]
    return '*' * len(clean)


def _mask_thai_id(thai_id: str) -> str:
    """
    Mask Thai citizen ID, showing only last 4 digits
    Example: 1-2345-67890-12-3 -> *-****-*****-**-3
    """
    # Preserve format if hyphenated
    if '-' in thai_id:
        parts = thai_id.split('-')
        if len(parts) == 5:
            return '*-****-*****-**-' + parts[-1]
    
    # Clean format
    clean = thai_id.replace('-', '')
    if len(clean) >= 4:
        return '*' * (len(clean) - 4) + clean[-4:]
    return '*' * len(clean)


def _mask_email(email: str) -> str:
    """
    Mask email address
    Example: user@example.com -> u***@example.com
    """
    if '@' in email:
        local, domain = email.split('@', 1)
        if len(local) > 2:
            return local[0] + '***' + '@' + domain
        elif len(local) > 0:
            return local[0] + '***@' + domain
    return '***@***.***'


def _mask_phone(phone: str) -> str:
    """
    Mask phone number, showing only last 4 digits
    Example: 081-234-5678 -> ***-***-5678
    """
    # Keep only digits
    digits = ''.join(c for c in phone if c.isdigit())
    
    if len(digits) >= 4:
        # Preserve format if possible
        if '-' in phone:
            parts = phone.split('-')
            masked_parts = ['*' * len(part) for part in parts[:-1]]
            masked_parts.append(parts[-1])
            return '-'.join(masked_parts)
        return '*' * (len(digits) - 4) + digits[-4:]
    return '*' * len(digits)
