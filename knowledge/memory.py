import sqlite3
from pathlib import Path

DB = Path.home() / ".kagent_gate_ai.db"

def init_db():
    with sqlite3.connect(DB) as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS knowledge (id INTEGER PRIMARY KEY, content TEXT)"
        )

def save_knowledge(text: str):
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO knowledge(content) VALUES(?)", (text,))
