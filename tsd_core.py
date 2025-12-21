"""
TSD:CORE - Thai Symbolic Logic System

This module implements a formal logic system using Thai characters as symbolic operators.

Symbol Definitions:
    ก (ko) ≔ ⊕ (oplus/addition operator)
    ข (kho) ≔ ⊗ (otimes/multiplication operator)
    จ (cho) ≔ ⇒ (implies operator)

Logic Rules:
    ก⊕ข ⇒ ค (oplus operation implies ค)
    ค⊗๒ ⇒ ง (otimes operation implies ง)
    ง ⇒ พิสูจน์ (ง implies proof)
    พิสูจน์ ⇒ ผ่าน (proof implies pass)

Grammar:
    ไวยากรณ์ ≔ ขยาย (syntax/grammar is expansion)
    ขยาย ⇒ EXPR⊗EXPR (expansion implies expression multiplication)

System:
    ระบบ ⇒ ทำงาน (system implies working)
    ทำงาน ⇒ หยุด (working implies stop)
"""


class TSDCore:
    """Thai Symbolic Logic System Core Implementation"""
    
    def __init__(self):
        # Symbol definitions
        self.symbols = {
            'ก': '⊕',  # oplus
            'ข': '⊗',  # otimes
            'จ': '⇒',  # implies
        }
        
        # Reverse mapping
        self.reverse_symbols = {v: k for k, v in self.symbols.items()}
        
        # Logic rules for implications
        self.implications = {
            ('⊕', 'ก', 'ข'): 'ค',
            ('⊗', 'ค', '๒'): 'ง',
            'ง': 'พิสูจน์',
            'พิสูจน์': 'ผ่าน',
        }
        
        # Grammar rules
        self.grammar = {
            'ไวยากรณ์': 'ขยาย',
            'ขยาย': ('EXPR', '⊗', 'EXPR'),
        }
        
        # System state
        self.system_states = {
            'ระบบ': 'ทำงาน',
            'ทำงาน': 'หยุด',
        }
        
        self.current_state = 'ระบบ'
    
    def get_symbol(self, thai_char):
        """Get the symbolic operator for a Thai character"""
        return self.symbols.get(thai_char)
    
    def get_thai_char(self, symbol):
        """Get the Thai character for a symbolic operator"""
        return self.reverse_symbols.get(symbol)
    
    def oplus(self, a, b):
        """⊕ operator (addition/disjunction)"""
        return ('⊕', a, b)
    
    def otimes(self, a, b):
        """⊗ operator (multiplication/conjunction)"""
        return ('⊗', a, b)
    
    def implies(self, a, b):
        """⇒ operator (implication)"""
        return ('⇒', a, b)
    
    def evaluate_implication(self, expr):
        """Evaluate an implication based on defined rules"""
        if isinstance(expr, tuple) and len(expr) == 3:
            # expr is in format (operator, left, right)
            # Check if this matches any implication rule
            if expr in self.implications:
                return self.implications[expr]
        
        # Check single element implications
        if expr in self.implications:
            return self.implications[expr]
        
        return None
    
    def expand_grammar(self):
        """Expand grammar according to ไวยากรณ์ rule"""
        base = self.grammar['ไวยากรณ์']
        expansion = self.grammar.get(base)
        return expansion
    
    def step_system(self):
        """Step the system state forward"""
        if self.current_state in self.system_states:
            next_state = self.system_states[self.current_state]
            self.current_state = next_state
            return next_state
        return self.current_state
    
    def get_system_state(self):
        """Get the current system state"""
        return self.current_state
    
    def prove(self):
        """Execute the proof chain: ง ⇒ พิสูจน์ ⇒ ผ่าน"""
        result = []
        
        # Start with ง
        current = 'ง'
        result.append(current)
        
        # ง ⇒ พิสูจน์
        current = self.implications.get(current)
        if current:
            result.append(current)
        
        # พิสูจน์ ⇒ ผ่าน
        current = self.implications.get(current)
        if current:
            result.append(current)
        
        return result


def main():
    """Demonstrate the TSD:CORE system"""
    tsd = TSDCore()
    
    print("=== TSD:CORE Thai Symbolic Logic System ===\n")
    
    # Show symbol mappings
    print("Symbol Definitions:")
    for thai, symbol in tsd.symbols.items():
        print(f"  {thai} ≔ {symbol}")
    print()
    
    # Test operators
    print("Operators:")
    expr1 = tsd.oplus('ก', 'ข')
    print(f"  ก ⊕ ข = {expr1}")
    
    # Test implication evaluation
    result = tsd.evaluate_implication(expr1)
    if result:
        print(f"  ก⊕ข ⇒ {result}")
    print()
    
    # Test grammar expansion
    print("Grammar:")
    expansion = tsd.expand_grammar()
    print(f"  ไวยากรณ์ ≔ ขยาย")
    print(f"  ขยาย ⇒ {expansion}")
    print()
    
    # Test system state
    print("System State:")
    print(f"  Initial: {tsd.get_system_state()}")
    tsd.step_system()
    print(f"  After step: {tsd.get_system_state()}")
    tsd.step_system()
    print(f"  After step: {tsd.get_system_state()}")
    print()
    
    # Test proof chain
    print("Proof Chain:")
    proof = tsd.prove()
    print(f"  {' ⇒ '.join(proof)}")
    print()


if __name__ == '__main__':
    main()
