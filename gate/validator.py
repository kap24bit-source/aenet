import json
from jsonschema import validate, ValidationError

from pathlib import Path

# Schema is in the llm subdirectory
_SCHEMA_PATH = Path(__file__).parent / "llm" / "llm_schema.json"
SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))

class LLMValidationError(Exception):
    pass

def validate_llm_output(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise LLMValidationError("LLM output is not valid JSON")

    try:
        validate(instance=data, schema=SCHEMA)
    except ValidationError as e:
        raise LLMValidationError(f"Schema violation: {e.message}")

    return data
