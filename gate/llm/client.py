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
