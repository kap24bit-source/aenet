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


def ask_llm(prompt: str) -> str:
    """
    Placeholder for LLM client function
    
    Args:
        prompt: User prompt
        
    Returns:
        LLM response (stub returns empty JSON)
    """
    return '{"type": "knowledge", "content": "", "confidence": 0.0}'

