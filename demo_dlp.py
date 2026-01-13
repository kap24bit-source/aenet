#!/usr/bin/env python3
"""
DLP System Demo
ตัวอย่างการใช้งานระบบ DLP
"""

from gate.dlp.scanner import DLPScanner
from gate.dlp.policy import DLPPolicy, Action
from gate.dlp.audit import DLPAuditLogger
from gate.sanitizer.clean import redact_detections
from pathlib import Path


def print_header(text):
    """Print section header"""
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}\n")


def demo_scanner():
    """Demonstrate DLP scanner capabilities"""
    print_header("DLP Scanner Demo")
    
    scanner = DLPScanner()
    
    test_cases = [
        ("AWS Access Key", "AKIAIOSFODNN7EXAMPLE"),
        ("GitHub Token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
        ("Thai Citizen ID", "1-2345-67890-12-3"),
        ("Email", "user@example.com"),
        ("Credit Card", "4111-1111-1111-1111"),
        ("Private Key", "-----BEGIN RSA PRIVATE KEY-----"),
    ]
    
    for name, text in test_cases:
        detections = scanner.scan(text)
        if detections:
            print(f"✓ Detected: {name}")
            for d in detections:
                print(f"  Pattern: {d.pattern_type}")
                print(f"  Confidence: {d.confidence:.2f}")
        else:
            print(f"✗ No detection: {name}")
        print()


def demo_policy():
    """Demonstrate policy engine"""
    print_header("Policy Engine Demo")
    
    config_path = Path(__file__).parent / "configs" / "dlp_policy.json"
    policy = DLPPolicy(config_path if config_path.exists() else None)
    
    print(f"Policy enabled: {policy.enabled}")
    print(f"Total rules: {len(policy.rules)}")
    print()
    
    # Show some example rules
    examples = ['aws_access_key', 'github_token', 'thai_citizen_id', 'email']
    
    for pattern_type in examples:
        rule = policy.get_rule(pattern_type)
        if rule:
            print(f"{pattern_type}:")
            print(f"  Severity: {rule.severity.value}")
            print(f"  Action: {rule.action.value}")
            print(f"  Description: {rule.description}")
            print()


def demo_redaction():
    """Demonstrate redaction and masking"""
    print_header("Redaction & Masking Demo")
    
    scanner = DLPScanner()
    
    test_cases = [
        "AWS Key: AKIAIOSFODNN7EXAMPLE",
        "Email: john.doe@example.com",
        "Phone: 081-234-5678",
        "Card: 4111-1111-1111-1111",
        "Thai ID: 1-2345-67890-12-3",
    ]
    
    for text in test_cases:
        detections = scanner.scan(text)
        redacted = redact_detections(text, detections)
        
        print(f"Original: {text}")
        print(f"Redacted: {redacted}")
        print()


def demo_audit():
    """Demonstrate audit logging"""
    print_header("Audit Logging Demo")
    
    scanner = DLPScanner()
    logger = DLPAuditLogger()
    policy = DLPPolicy()
    
    # Simulate some detections
    test_text = "AWS: AKIAIOSFODNN7EXAMPLE, Email: user@example.com"
    detections = scanner.scan(test_text)
    
    print(f"Scanning: {test_text}")
    print(f"Found {len(detections)} detections\n")
    
    for detection in detections:
        severity = policy.get_severity(detection.pattern_type)
        action = policy.get_action(detection.pattern_type)
        
        # Log it
        entry_id = logger.log(
            pattern_type=detection.pattern_type,
            severity=severity.value,
            action=action.value,
            matched_text=detection.matched_text,
            confidence=detection.confidence,
            source='demo'
        )
        
        print(f"Logged entry #{entry_id}:")
        print(f"  Type: {detection.pattern_type}")
        print(f"  Severity: {severity.value}")
        print(f"  Action: {action.value}")
        print()
    
    # Show statistics
    stats = logger.get_statistics()
    print("Audit Statistics:")
    print(f"  Total detections: {stats['total_detections']}")
    print(f"  By severity: {stats['by_severity']}")
    print(f"  By action: {stats['by_action']}")


def demo_integration():
    """Demonstrate full integration"""
    print_header("Full Integration Demo")
    
    scanner = DLPScanner()
    policy = DLPPolicy()
    logger = DLPAuditLogger()
    
    # Simulate processing sensitive data
    text = "AWS key: AKIAIOSFODNN7EXAMPLE in production"
    
    print(f"Processing: {text}\n")
    
    # Scan
    detections = scanner.scan(text)
    print(f"Detections: {len(detections)}")
    
    # Apply policy
    should_block = False
    for detection in detections:
        severity = policy.get_severity(detection.pattern_type)
        action = policy.get_action(detection.pattern_type)
        
        print(f"  → {detection.pattern_type}: {severity.value} / {action.value}")
        
        # Log
        logger.log(
            pattern_type=detection.pattern_type,
            severity=severity.value,
            action=action.value,
            matched_text=detection.matched_text,
            confidence=detection.confidence,
            source='integration_demo'
        )
        
        if action == Action.BLOCK:
            should_block = True
    
    print()
    if should_block:
        print("❌ Result: BLOCKED - Processing stopped due to sensitive data")
    else:
        redacted = redact_detections(text, detections)
        print(f"✓ Result: ALLOWED (redacted)")
        print(f"  Redacted text: {redacted}")


def main():
    """Run all demos"""
    print("\n" + "=" * 60)
    print("  DLP System Demonstration")
    print("  ระบบป้องกันการรั่วไหลของข้อมูล")
    print("=" * 60)
    
    demo_scanner()
    demo_policy()
    demo_redaction()
    demo_audit()
    demo_integration()
    
    print_header("Demo Complete")
    print("✓ All demos completed successfully")
    print("\nFor more information, see DLP_README.md\n")


if __name__ == "__main__":
    main()
