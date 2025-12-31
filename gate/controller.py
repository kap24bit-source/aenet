from gate.policy.rules import allow_topic
from gate.llm.client import ask_llm
from gate.sanitizer.clean import sanitize
from gate.intake.ingest import ingest
from core.executor import execute
from knowledge.memory import init_db

def gate_entry():
    init_db()
    user_input = input(">> ")
    topic = "programming_concept"

    if allow_topic(topic):
        raw = ask_llm(user_input)
        clean = sanitize(raw)
        ingest(clean)

    execute(user_input)
