# KAGENT Gate + AI + KFAST (Integrated System)

An integrated system combining:
- **Gate**: External AI knowledge source (read-only, one-way inbound)
- **Core**: Unified executor supporting plain text and KFAST code
- **Knowledge**: Persistent memory with SQLite backend
- **KFAST**: Lightweight runtime with custom language, bytecode VM, and persistent commands

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   User Input                     │
└───────────────────────┬─────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────┐
│                 Gate Controller                  │
│  ┌─────────────────────────────────────────┐    │
│  │ Policy → LLM → Sanitizer → Intake       │    │
│  └─────────────────────────────────────────┘    │
└───────────────────────┬─────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────┐
│               Core Executor                      │
│  ┌─────────────────────────────────────────┐    │
│  │ Plain Text ──┬── KFAST Code             │    │
│  │     │        │      │                   │    │
│  │     ▼        │      ▼                   │    │
│  │   Print      │    VM + Kernel           │    │
│  └─────────────────────────────────────────┘    │
└───────────────────────┬─────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────┐
│           Knowledge / Command Store              │
│  ┌─────────────────────────────────────────┐    │
│  │ SQLite: knowledge + KFAST commands       │   │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

## Quick Start

```bash
python main.py
```

## Commands

At the prompt, you can:
- Enter plain text (printed via executor)
- Enter KFAST code (executed via VM)
- Use built-in commands:
  - `/help` - Show help
  - `/cmd list` - List saved commands
  - `/cmd save <name>` - Save KFAST code as a named command
  - `/cmd run <name>` - Run a saved command
  - `/cmd show <name>` - Show command source

## KFAST Language

KFAST is a lightweight scripting language with Thai language support.

### Run a KFAST file directly:
```bash
python kfast_system.py run app.kap
```

### CLI for persistent commands:
```bash
python kfast_system.py cmd save ทักทาย examples/hello.kap
python kfast_system.py cmd run ทักทาย
python kfast_system.py cmd list
```

## Data Flow

- External AI = Knowledge Source (Read-only)
- Internal System = Authority
- Data Flow = One Way Inbound Only
