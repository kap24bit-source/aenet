from typing import Optional

SYSTEM_RULES = """\
You MUST reply in JSON only.
No markdown. No explanation. No code.
Follow this schema strictly:

{
  "type": "knowledge",
  "content": "<plain text only>",
  "confidence": 0.0
}

If you cannot answer, still return valid JSON with empty content.
"""


def ask_llm(prompt: str) -> Optional[str]:
    """Send prompt to LLM and get response.
    
    Currently returns None as placeholder.
    In production, this would connect to an actual LLM service.
    """
    # Placeholder - no actual LLM connection
    # Returns None to indicate no response available
    return None
