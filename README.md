# aenet

## TSD:CORE - Thai Symbolic Logic System

This repository implements a formal logic system using Thai characters as symbolic operators.

### Symbol Definitions

The system defines the following symbolic operators:

- `ก` (ko) ≔ `⊕` (oplus/addition operator)
- `ข` (kho) ≔ `⊗` (otimes/multiplication operator)
- `จ` (cho) ≔ `⇒` (implies operator)

### Logic Rules

The system implements the following implication rules:

1. `ก⊕ข ⇒ ค` - oplus operation implies ค
2. `ค⊗๒ ⇒ ง` - otimes operation implies ง
3. `ง ⇒ พิสูจน์` - ง implies proof
4. `พิสูจน์ ⇒ ผ่าน` - proof implies pass

### Grammar

The system includes grammar expansion rules:

- `ไวยากรณ์ ≔ ขยาย` - syntax/grammar is expansion
- `ขยาย ⇒ EXPR⊗EXPR` - expansion implies expression multiplication

### System States

The system manages state transitions:

- `ระบบ ⇒ ทำงาน` - system implies working
- `ทำงาน ⇒ หยุด` - working implies stop

### Usage

Run the demonstration:

```bash
python tsd_core.py
```

Run the tests:

```bash
python -m unittest test_tsd_core -v
```

### Example

```python
from tsd_core import TSDCore

# Initialize the system
tsd = TSDCore()

# Get symbol mappings
print(tsd.get_symbol('ก'))  # Output: ⊕

# Create expressions
expr = tsd.oplus('ก', 'ข')  # ก ⊕ ข

# Evaluate implications
result = tsd.evaluate_implication(expr)  # Output: ค

# Execute proof chain
proof = tsd.prove()  # Output: ['ง', 'พิสูจน์', 'ผ่าน']

# Step through system states
tsd.step_system()  # ระบบ → ทำงาน
tsd.step_system()  # ทำงาน → หยุด
```