"""
Tests for TSD:CORE Thai Symbolic Logic System
"""

import unittest
from tsd_core import TSDCore


class TestTSDCore(unittest.TestCase):
    """Test cases for TSD:CORE system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.tsd = TSDCore()
    
    def test_symbol_definitions(self):
        """Test symbol mappings: ก≔⊕, ข≔⊗, จ≔⇒"""
        self.assertEqual(self.tsd.get_symbol('ก'), '⊕')
        self.assertEqual(self.tsd.get_symbol('ข'), '⊗')
        self.assertEqual(self.tsd.get_symbol('จ'), '⇒')
    
    def test_reverse_symbol_mapping(self):
        """Test reverse symbol lookups"""
        self.assertEqual(self.tsd.get_thai_char('⊕'), 'ก')
        self.assertEqual(self.tsd.get_thai_char('⊗'), 'ข')
        self.assertEqual(self.tsd.get_thai_char('⇒'), 'จ')
    
    def test_oplus_operator(self):
        """Test ⊕ (oplus) operator"""
        result = self.tsd.oplus('ก', 'ข')
        self.assertEqual(result, ('⊕', 'ก', 'ข'))
    
    def test_otimes_operator(self):
        """Test ⊗ (otimes) operator"""
        result = self.tsd.otimes('EXPR', 'EXPR')
        self.assertEqual(result, ('⊗', 'EXPR', 'EXPR'))
    
    def test_implies_operator(self):
        """Test ⇒ (implies) operator"""
        result = self.tsd.implies('A', 'B')
        self.assertEqual(result, ('⇒', 'A', 'B'))
    
    def test_implication_rule_1(self):
        """Test ก⊕ข ⇒ ค"""
        expr = ('⊕', 'ก', 'ข')
        result = self.tsd.evaluate_implication(expr)
        self.assertEqual(result, 'ค')
    
    def test_implication_rule_2(self):
        """Test ค⊗๒ ⇒ ง"""
        expr = ('⊗', 'ค', '๒')
        result = self.tsd.evaluate_implication(expr)
        self.assertEqual(result, 'ง')
    
    def test_implication_rule_3(self):
        """Test ง ⇒ พิสูจน์"""
        result = self.tsd.evaluate_implication('ง')
        self.assertEqual(result, 'พิสูจน์')
    
    def test_implication_rule_4(self):
        """Test พิสูจน์ ⇒ ผ่าน"""
        result = self.tsd.evaluate_implication('พิสูจน์')
        self.assertEqual(result, 'ผ่าน')
    
    def test_grammar_definition(self):
        """Test ไวยากรณ์ ≔ ขยาย"""
        self.assertEqual(self.tsd.grammar['ไวยากรณ์'], 'ขยาย')
    
    def test_grammar_expansion(self):
        """Test ขยาย ⇒ EXPR⊗EXPR"""
        expansion = self.tsd.expand_grammar()
        self.assertEqual(expansion, ('EXPR', '⊗', 'EXPR'))
    
    def test_system_initial_state(self):
        """Test ระบบ initial state"""
        self.assertEqual(self.tsd.get_system_state(), 'ระบบ')
    
    def test_system_state_transition_1(self):
        """Test ระบบ ⇒ ทำงาน"""
        next_state = self.tsd.step_system()
        self.assertEqual(next_state, 'ทำงาน')
        self.assertEqual(self.tsd.get_system_state(), 'ทำงาน')
    
    def test_system_state_transition_2(self):
        """Test ทำงาน ⇒ หยุด"""
        self.tsd.step_system()  # ระบบ → ทำงาน
        next_state = self.tsd.step_system()  # ทำงาน → หยุด
        self.assertEqual(next_state, 'หยุด')
        self.assertEqual(self.tsd.get_system_state(), 'หยุด')
    
    def test_proof_chain(self):
        """Test complete proof chain: ง ⇒ พิสูจน์ ⇒ ผ่าน"""
        proof = self.tsd.prove()
        self.assertEqual(len(proof), 3)
        self.assertEqual(proof[0], 'ง')
        self.assertEqual(proof[1], 'พิสูจน์')
        self.assertEqual(proof[2], 'ผ่าน')
    
    def test_complete_workflow(self):
        """Test complete workflow integrating all components"""
        # Start with symbols
        self.assertEqual(self.tsd.get_symbol('ก'), '⊕')
        
        # Apply first implication rule
        expr1 = self.tsd.oplus('ก', 'ข')
        result1 = self.tsd.evaluate_implication(expr1)
        self.assertEqual(result1, 'ค')
        
        # Apply second implication rule
        expr2 = self.tsd.otimes(result1, '๒')
        result2 = self.tsd.evaluate_implication(expr2)
        self.assertEqual(result2, 'ง')
        
        # Complete proof
        proof = self.tsd.prove()
        self.assertEqual(proof[-1], 'ผ่าน')
        
        # Verify system states
        self.tsd.step_system()
        self.assertEqual(self.tsd.get_system_state(), 'ทำงาน')


if __name__ == '__main__':
    unittest.main()
