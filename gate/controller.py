from gate.policy.rules import allow_topic
from gate.llm.client import ask_llm
from gate.sanitizer.clean import sanitize
from gate.intake.ingest import ingest
from gate.validator import validate_llm_output, LLMValidationError
from core.executor import execute, get_kernel
from knowledge.memory import init_db, save_command, load_command, list_commands


def gate_entry():
    """Main entry point for the integrated gate system.
    
    Flow:
    1. Initialize database (knowledge + KFAST command store)
    2. Read user input
    3. If input is a command (starts with /), handle it
    4. Otherwise, process through gate pipeline (policy -> LLM -> sanitize -> ingest)
    5. Execute through the unified executor (supports plain text and KFAST code)
    """
    init_db()
    
    print("=== KAGENT Gate + AI + KFAST (Integrated System) ===")
    print("Commands: /cmd list | /cmd save <name> | /cmd run <name> | /help")
    print("Or enter KFAST code or plain text:")
    
    user_input = input(">> ")
    
    # Handle built-in commands
    if user_input.startswith("/"):
        handle_command(user_input)
        return
    
    topic = "programming_concept"

    if allow_topic(topic):
        raw = ask_llm(user_input)
        if raw:
            clean = sanitize(raw)
            ingest(clean)

    execute(user_input)


def handle_command(cmd: str):
    """Handle built-in gate commands."""
    parts = cmd.strip().split()
    
    if not parts:
        return
    
    if parts[0] == "/help":
        print("Available commands:")
        print("  /cmd list          - List saved commands")
        print("  /cmd save <name>   - Save next input as command")
        print("  /cmd run <name>    - Run a saved command")
        print("  /cmd show <name>   - Show command source")
        print("  /help              - Show this help")
        return
    
    if parts[0] == "/cmd":
        if len(parts) < 2:
            print("Usage: /cmd <list|save|run|show> [name]")
            return
        
        subcmd = parts[1]
        
        if subcmd == "list":
            commands = list_commands()
            if commands:
                print("Saved commands:")
                for name in commands:
                    print(f"  - {name}")
            else:
                print("No saved commands.")
            return
        
        if subcmd == "save":
            if len(parts) < 3:
                print("Usage: /cmd save <name>")
                return
            name = parts[2]
            print(f"Enter KFAST code for '{name}' (end with empty line):")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
            src = "\n".join(lines)
            save_command(name, src)
            print(f"Command '{name}' saved.")
            return
        
        if subcmd == "run":
            if len(parts) < 3:
                print("Usage: /cmd run <name>")
                return
            name = parts[2]
            src = load_command(name)
            if src is None:
                print(f"Command '{name}' not found.")
                return
            print(f"Running '{name}'...")
            execute(src)
            return
        
        if subcmd == "show":
            if len(parts) < 3:
                print("Usage: /cmd show <name>")
                return
            name = parts[2]
            src = load_command(name)
            if src is None:
                print(f"Command '{name}' not found.")
                return
            print(f"--- {name} ---")
            print(src)
            print("---")
            return
        
        print(f"Unknown subcommand: {subcmd}")
        return
    
    print(f"Unknown command: {parts[0]}")
