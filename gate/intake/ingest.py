from knowledge.memory import save_knowledge

def ingest(text: str):
    if len(text) < 20:
        return
    save_knowledge(text)
