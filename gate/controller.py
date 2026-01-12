from gate.policy.rules import allow_topic
from gate.llm.client import ask_llm
from gate.sanitizer.clean import sanitize, redact_detections
from gate.intake.ingest import ingest
from core.executor import execute
from knowledge.memory import init_db
from gate.dlp.scanner import DLPScanner
from gate.dlp.policy import DLPPolicy, Action
from gate.dlp.audit import DLPAuditLogger
from pathlib import Path


# Initialize DLP components
_dlp_scanner = None
_dlp_policy = None
_dlp_logger = None


def _init_dlp():
    """Initialize DLP components"""
    global _dlp_scanner, _dlp_policy, _dlp_logger
    
    if _dlp_scanner is None:
        _dlp_scanner = DLPScanner()
    
    if _dlp_policy is None:
        config_path = Path(__file__).parent.parent / "configs" / "dlp_policy.json"
        _dlp_policy = DLPPolicy(config_path if config_path.exists() else None)
    
    if _dlp_logger is None:
        _dlp_logger = DLPAuditLogger()
    
    return _dlp_scanner, _dlp_policy, _dlp_logger


def _process_with_dlp(text: str, source: str = "llm_response") -> tuple[str, bool]:
    """
    Process text with DLP scanning
    
    Args:
        text: Text to process
        source: Source of the text
        
    Returns:
        Tuple of (processed_text, should_block)
    """
    scanner, policy, logger = _init_dlp()
    
    # Check if DLP is enabled
    if not policy.enabled:
        return text, False
    
    # Scan for sensitive data
    detections = scanner.scan(text)
    
    if not detections:
        return text, False
    
    # Process each detection
    should_block = False
    should_quarantine = False
    
    for detection in detections:
        # Get policy action
        action = policy.get_action(detection.pattern_type)
        severity = policy.get_severity(detection.pattern_type)
        
        # Log the detection
        logger.log(
            pattern_type=detection.pattern_type,
            severity=severity.value,
            action=action.value,
            matched_text=detection.matched_text,
            confidence=detection.confidence,
            source=source
        )
        
        # Determine if we should block
        if action == Action.BLOCK:
            should_block = True
            print(f"[DLP BLOCK] {severity.value}: {detection.pattern_type} detected")
        elif action == Action.QUARANTINE:
            should_quarantine = True
            print(f"[DLP QUARANTINE] {severity.value}: {detection.pattern_type} detected")
        elif action == Action.WARN:
            print(f"[DLP WARN] {severity.value}: {detection.pattern_type} detected")
        elif action == Action.LOG:
            print(f"[DLP LOG] {severity.value}: {detection.pattern_type} detected")
    
    # Handle quarantine
    if should_quarantine:
        _quarantine_data(text, detections, policy)
    
    # Redact sensitive data if not blocking
    if not should_block:
        text = redact_detections(text, detections)
    
    return text, should_block


def _quarantine_data(text: str, detections, policy):
    """
    Quarantine sensitive data
    
    Args:
        text: Original text
        detections: List of detections
        policy: DLP policy
    """
    import json
    from datetime import datetime
    
    quarantine_file = policy.quarantine_path / f"quarantine_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    data = {
        'timestamp': datetime.now().isoformat(),
        'text': text,
        'detections': [
            {
                'pattern_type': d.pattern_type,
                'matched_text': d.matched_text,
                'confidence': d.confidence
            }
            for d in detections
        ]
    }
    
    try:
        with open(quarantine_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"[DLP] Data quarantined to: {quarantine_file}")
    except Exception as e:
        print(f"[DLP ERROR] Failed to quarantine data: {e}")


def gate_entry():
    init_db()
    user_input = input(">> ")
    topic = "programming_concept"

    if allow_topic(topic):
        raw = ask_llm(user_input)
        
        # DLP scanning and processing
        processed, blocked = _process_with_dlp(raw, source="llm_response")
        
        if blocked:
            print("[DLP] Processing blocked due to sensitive data detection")
            return
        
        # Continue with sanitization and ingestion
        clean = sanitize(processed)
        ingest(clean)

    execute(user_input)
