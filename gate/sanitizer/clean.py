import re

def sanitize(text: str) -> str:
    text = re.sub(r"/\S+", "[PATH]", text)
    text = re.sub(r"[A-Za-z0-9]{20,}", "[REDACTED]", text)
    return text
