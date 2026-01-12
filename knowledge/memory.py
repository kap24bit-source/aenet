import sqlite3
from pathlib import Path
from typing import Optional, List

from kfast_system import CommandStore

DB = Path.home() / ".kagent_gate_ai.db"

# Shared command store for persistent memory
_store: Optional[CommandStore] = None


def get_store() -> CommandStore:
    """Get or create the shared CommandStore."""
    global _store
    if _store is None:
        _store = CommandStore()
    return _store


def init_db():
    """Initialize both legacy database and KFAST command store."""
    # Legacy DB for backward compatibility
    with sqlite3.connect(DB) as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS knowledge (id INTEGER PRIMARY KEY, content TEXT)"
        )
    # Initialize KFAST store (automatic via SQLite)
    get_store()


def save_knowledge(text: str):
    """Save knowledge to legacy database."""
    with sqlite3.connect(DB) as c:
        c.execute("INSERT INTO knowledge(content) VALUES(?)", (text,))


def save_command(name: str, src: str):
    """Save a KFAST command to persistent store."""
    get_store().save(name, src)


def load_command(name: str) -> Optional[str]:
    """Load a KFAST command from persistent store."""
    return get_store().load(name)


def list_commands(prefix: Optional[str] = None) -> List[str]:
    """List all stored commands."""
    return get_store().list(prefix)


def delete_command(name: str) -> bool:
    """Delete a stored command."""
    return get_store().delete(name)
