#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KFAST v0.1

เป้าหมาย
- Runtime แบบ “เบาและเร็ว”: lex -> parse -> bytecode -> VM (stack-based)
- Kernel syscall แบบแยก namespace (SYS/MEM/PROC/IPC/CMD)
- CMD = persistent command memory (SQLite) สำหรับ “จำ/เรียกใช้” คำสั่งการทำงาน

แนวคิดการใช้งาน
1) รันไฟล์ .kap
   python3 kfast_system.py run app.kap

2) จำคำสั่ง (เก็บ source ของ .kap) และเรียกใช้ภายหลัง
   python3 kfast_system.py cmd save ทักทาย examples/hello.kap
   python3 kfast_system.py cmd run ทักทาย

3) ใช้จากในภาษา .kap ผ่านโมดูล CMD
   CMD.จำไฟล์⟨"ทักทาย"⋄"examples/hello.kap"⟩
   CMD.ทำ⟨"ทักทาย"⟩

ข้อจำกัด v0.1
- รองรับ loop เฉพาะ while
- if ต้องมี else (ใช้ ':' เป็นตัวคั่น)
- ฟังก์ชัน global (ƒ) เรียกได้ด้วย fn⟨...⟩ หรือ GLOBAL.fn⟨...⟩

ไม่มี dependency ภายนอก (ใช้เฉพาะ stdlib)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import ast
import json
import re
import sqlite3
import sys
import threading
import time

# ============================================================
# 1) LANGUAGE CONSTANTS (subset)
# ============================================================

GLYPH_BLOCK_L = "⟦"
GLYPH_BLOCK_R = "⟧"
GLYPH_PARAM_L = "⟨"
GLYPH_PARAM_R = "⟩"
GLYPH_ASSIGN = "⟶"
GLYPH_SEP = "⋄"
GLYPH_TYPE = "∷"

KW_ENTRY_START = "⚙"
KW_ENTRY_END = "■"
KW_IF = "?"
KW_ELSE = ":"
KW_RETURN = "✓"
KW_EMIT = "☍"
KW_LISTEN = "☊"
KW_MODULE = "⌁"
KW_LET = "☰"
KW_LOOP = "↻"
KW_FN = "ƒ"

TYPES = {"num", "text", "bool", "null", "list", "map", "signal", "any"}

# ============================================================
# 2) LEXER
#    แก้ bug เดิม: การอ่าน STRING ไม่ใช้ m.group(1)
# ============================================================

@dataclass
class Token:
    kind: str
    value: str
    pos: int


_TOKEN_REGEX: List[Tuple[str, str]] = [
    ("WS", r"[ \t\r\n]+"),
    # รองรับ # และ // เป็น comment (ระวัง: ไม่มี operator // ในภาษาอยู่แล้ว)
    ("COMMENT", r"#.*|//.*"),
    ("GLYPH", r"[⟦⟧⟨⟩⟶⋄∷⚙■\?:✓☍☊⌁☰↻ƒ]"),
    ("BOOL", r"\b(?:true|false)\b"),
    ("NULL", r"\bnull\b"),
    ("NUMBER", r"\b\d+(?:\.\d+)?\b"),
    # encrypted-string: @"..." (ใช้ parser เดียวกับ STRING แล้วค่อย decode เพิ่มได้ภายหลัง)
    ("ENC_STRING", r"@\s*\"(?:[^\"\\]|\\.)*\""),
    ("STRING", r"\"(?:[^\"\\]|\\.)*\""),
    ("OP", r"(==|!=|>=|<=|&&|\|\||[+\-*/><!])"),
    ("LBRACE", r"\{"),
    ("RBRACE", r"\}"),
    ("LBRACK", r"\["),
    ("RBRACK", r"\]"),
    ("COMMA", r","),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("DOT", r"\."),
    ("IDENT", r"[A-Za-z_\u0E00-\u0E7F][A-Za-z0-9_\u0E00-\u0E7F]*"),
]

_TOKEN_RE = re.compile("|".join(f"(?P<{k}>{v})" for k, v in _TOKEN_REGEX), re.UNICODE)


def _parse_string_token(text_with_quotes: str) -> str:
    """แปลง token STRING ให้เป็น Python str โดยรักษา unicode ไทยและ escape"""
    try:
        # text_with_quotes มีรูปแบบ "..." ตาม lexer
        return ast.literal_eval(text_with_quotes)
    except Exception:
        # fallback แบบไม่เคร่งครัด
        if len(text_with_quotes) >= 2 and text_with_quotes[0] == '"' and text_with_quotes[-1] == '"':
            return text_with_quotes[1:-1]
        return text_with_quotes


def lex(src: str) -> List[Token]:
    out: List[Token] = []
    i = 0
    while i < len(src):
        m = _TOKEN_RE.match(src, i)
        if not m:
            raise SyntaxError(f"LEX ERROR @ {i}: {src[i:i+20]!r}")
        kind = m.lastgroup or "?"
        text = m.group(0)
        if kind in ("WS", "COMMENT"):
            i = m.end()
            continue

        if kind == "STRING":
            out.append(Token("STRING", _parse_string_token(text), i))
        elif kind == "ENC_STRING":
            # รูปแบบ @"..." อาจมีช่องว่างหลัง @
            q = text.find('"')
            raw = text[q:] if q != -1 else '""'
            out.append(Token("STRING", _parse_string_token(raw), i))
        else:
            out.append(Token(kind, text, i))

        i = m.end()

    out.append(Token("EOF", "", len(src)))
    return out


# ============================================================
# 3) AST
# ============================================================

@dataclass
class Node:
    pass


@dataclass
class Program(Node):
    stmts: List[Node]


@dataclass
class Block(Node):
    stmts: List[Node]


@dataclass
class Entry(Node):
    body: Block


@dataclass
class ModuleDecl(Node):
    name: str
    params: Dict[str, Node]
    body: Block


@dataclass
class FnDecl(Node):
    name: str
    params: Dict[str, Node]
    body: Block


@dataclass
class LetDecl(Node):
    name: str
    typ: Optional[str]
    expr: Node


@dataclass
class Assign(Node):
    name: str
    expr: Node


@dataclass
class IfStmt(Node):
    cond: Node
    then_b: Block
    else_b: Block


@dataclass
class LoopStmt(Node):
    mode: str
    cond: Node
    body: Block


@dataclass
class Emit(Node):
    params: Dict[str, Node]


@dataclass
class Listen(Node):
    params: Dict[str, Node]


@dataclass
class Return(Node):
    expr: Node


@dataclass
class ExprStmt(Node):
    expr: Node


# ---- Expressions ----

@dataclass
class Literal(Node):
    value: Any


@dataclass
class Var(Node):
    name: str


@dataclass
class Call(Node):
    mod: str
    fn: str
    args: List[Node]


@dataclass
class Unary(Node):
    op: str
    right: Node


@dataclass
class Binary(Node):
    left: Node
    op: str
    right: Node


@dataclass
class MapLit(Node):
    items: List[Tuple[str, Node]]  # key string -> expr


@dataclass
class ListLit(Node):
    items: List[Node]


# ============================================================
# 4) PARSER
# ============================================================

class Parser:
    def __init__(self, tokens: List[Token]):
        self.toks = tokens
        self.i = 0

    def cur(self) -> Token:
        return self.toks[self.i]

    def eat(self, kind: str, value: Optional[str] = None) -> Token:
        t = self.cur()
        if t.kind != kind:
            raise SyntaxError(f"Expected {kind} got {t.kind} @ {t.pos}")
        if value is not None and t.value != value:
            raise SyntaxError(f"Expected {value!r} got {t.value!r} @ {t.pos}")
        self.i += 1
        return t

    def match(self, kind: str, value: Optional[str] = None) -> bool:
        t = self.cur()
        if t.kind != kind:
            return False
        if value is not None and t.value != value:
            return False
        return True

    def parse_program(self) -> Program:
        stmts: List[Node] = []
        # entry wrapper: ⟦ ⚙ ... ⟧ ... ⟦ ■ ... ⟧
        if self.match("GLYPH", GLYPH_BLOCK_L):
            save = self.i
            self.eat("GLYPH", GLYPH_BLOCK_L)
            if self.match("GLYPH", KW_ENTRY_START):
                self.i = save
                entry = self.parse_entry()
                return Program([entry])
            self.i = save

        while not self.match("EOF"):
            stmts.append(self.parse_stmt())
        return Program(stmts)

    def _peek_is_end_marker(self) -> bool:
        if not self.match("GLYPH", GLYPH_BLOCK_L):
            return False
        return (self.toks[self.i + 1].kind == "GLYPH" and self.toks[self.i + 1].value == KW_ENTRY_END)

    def parse_entry(self) -> Entry:
        self.eat("GLYPH", GLYPH_BLOCK_L)
        self.eat("GLYPH", KW_ENTRY_START)
        if self.match("IDENT"):
            self.eat("IDENT")
        self.eat("GLYPH", GLYPH_BLOCK_R)

        body_stmts: List[Node] = []
        while not (self.match("GLYPH", GLYPH_BLOCK_L) and self._peek_is_end_marker()):
            body_stmts.append(self.parse_stmt())

        self.eat("GLYPH", GLYPH_BLOCK_L)
        self.eat("GLYPH", KW_ENTRY_END)
        if self.match("IDENT"):
            self.eat("IDENT")
        self.eat("GLYPH", GLYPH_BLOCK_R)

        return Entry(Block(body_stmts))

    def parse_stmt(self) -> Node:
        if self.match("GLYPH", GLYPH_BLOCK_L):
            return self.parse_block()
        if self.match("GLYPH", KW_MODULE):
            return self.parse_module()
        if self.match("GLYPH", KW_FN):
            return self.parse_fn()
        if self.match("GLYPH", KW_LET):
            return self.parse_let()
        if self.match("GLYPH", KW_IF):
            return self.parse_if()
        if self.match("GLYPH", KW_LOOP):
            return self.parse_loop()
        if self.match("GLYPH", KW_EMIT):
            return self.parse_emit()
        if self.match("GLYPH", KW_LISTEN):
            return self.parse_listen()
        if self.match("GLYPH", KW_RETURN):
            return self.parse_return()

        # assign: IDENT ⟶ expr
        if self.match("IDENT") and self.toks[self.i + 1].kind == "GLYPH" and self.toks[self.i + 1].value == GLYPH_ASSIGN:
            name = self.eat("IDENT").value
            self.eat("GLYPH", GLYPH_ASSIGN)
            expr = self.parse_expr()
            return Assign(name, expr)

        expr = self.parse_expr()
        return ExprStmt(expr)

    def parse_block(self) -> Block:
        self.eat("GLYPH", GLYPH_BLOCK_L)
        stmts: List[Node] = []
        while not self.match("GLYPH", GLYPH_BLOCK_R):
            stmts.append(self.parse_stmt())
        self.eat("GLYPH", GLYPH_BLOCK_R)
        return Block(stmts)

    def parse_params(self) -> Dict[str, Node]:
        self.eat("GLYPH", GLYPH_PARAM_L)
        params: Dict[str, Node] = {}
        while not self.match("GLYPH", GLYPH_PARAM_R):
            key = self.eat("IDENT").value
            self.eat("GLYPH", GLYPH_ASSIGN)
            val = self.parse_expr()
            params[key] = val
            if self.match("GLYPH", GLYPH_SEP):
                self.eat("GLYPH", GLYPH_SEP)
            else:
                break
        self.eat("GLYPH", GLYPH_PARAM_R)
        return params

    def parse_module(self) -> ModuleDecl:
        self.eat("GLYPH", KW_MODULE)
        name = self.eat("IDENT").value
        params = self.parse_params()
        body = self.parse_block()
        return ModuleDecl(name, params, body)

    def parse_fn(self) -> FnDecl:
        self.eat("GLYPH", KW_FN)
        name = self.eat("IDENT").value
        params = self.parse_params()
        body = self.parse_block()
        return FnDecl(name, params, body)

    def parse_let(self) -> LetDecl:
        self.eat("GLYPH", KW_LET)
        name = self.eat("IDENT").value
        typ: Optional[str] = None
        if self.match("GLYPH", GLYPH_TYPE):
            self.eat("GLYPH", GLYPH_TYPE)
            typ = self.eat("IDENT").value
            if typ not in TYPES:
                raise SyntaxError(f"Unknown type {typ!r}")
        self.eat("GLYPH", GLYPH_ASSIGN)
        expr = self.parse_expr()
        return LetDecl(name, typ, expr)

    def parse_if(self) -> IfStmt:
        self.eat("GLYPH", KW_IF)
        cond = self.parse_expr()
        then_b = self.parse_block()
        self.eat("GLYPH", KW_ELSE)
        else_b = self.parse_block()
        return IfStmt(cond, then_b, else_b)

    def parse_loop(self) -> LoopStmt:
        self.eat("GLYPH", KW_LOOP)
        params = self.parse_params()
        mode_node = params.get("ชนิด") or params.get("mode")
        cond_node = params.get("เงื่อนไข") or params.get("cond")
        if not isinstance(mode_node, Literal) or not isinstance(mode_node.value, str):
            raise SyntaxError("loop requires ชนิด⟶\"while\"")
        if cond_node is None:
            raise SyntaxError("loop requires เงื่อนไข⟶(expr)")
        mode = mode_node.value
        if mode != "while":
            raise SyntaxError("v0.1 รองรับ loop เฉพาะ while")
        body = self.parse_block()
        return LoopStmt(mode=mode, cond=cond_node, body=body)

    def parse_emit(self) -> Emit:
        self.eat("GLYPH", KW_EMIT)
        params = self.parse_params()
        return Emit(params)

    def parse_listen(self) -> Listen:
        self.eat("GLYPH", KW_LISTEN)
        params = self.parse_params()
        return Listen(params)

    def parse_return(self) -> Return:
        self.eat("GLYPH", KW_RETURN)
        expr = self.parse_expr()
        return Return(expr)

    # ---- Expression parsing (precedence climbing) ----
    def parse_expr(self) -> Node:
        return self.parse_or()

    def parse_or(self) -> Node:
        node = self.parse_and()
        while self.match("OP", "||"):
            op = self.eat("OP").value
            right = self.parse_and()
            node = Binary(node, op, right)
        return node

    def parse_and(self) -> Node:
        node = self.parse_eq()
        while self.match("OP", "&&"):
            op = self.eat("OP").value
            right = self.parse_eq()
            node = Binary(node, op, right)
        return node

    def parse_eq(self) -> Node:
        node = self.parse_rel()
        while self.match("OP") and self.cur().value in ("==", "!="):
            op = self.eat("OP").value
            right = self.parse_rel()
            node = Binary(node, op, right)
        return node

    def parse_rel(self) -> Node:
        node = self.parse_add()
        while self.match("OP") and self.cur().value in (">", "<", ">=", "<="):
            op = self.eat("OP").value
            right = self.parse_add()
            node = Binary(node, op, right)
        return node

    def parse_add(self) -> Node:
        node = self.parse_mul()
        while self.match("OP") and self.cur().value in ("+", "-"):
            op = self.eat("OP").value
            right = self.parse_mul()
            node = Binary(node, op, right)
        return node

    def parse_mul(self) -> Node:
        node = self.parse_unary()
        while self.match("OP") and self.cur().value in ("*", "/"):
            op = self.eat("OP").value
            right = self.parse_unary()
            node = Binary(node, op, right)
        return node

    def parse_unary(self) -> Node:
        if self.match("OP") and self.cur().value in ("!", "-"):
            op = self.eat("OP").value
            right = self.parse_unary()
            return Unary(op, right)
        return self.parse_primary()

    def parse_primary(self) -> Node:
        if self.match("LPAREN"):
            self.eat("LPAREN")
            node = self.parse_expr()
            self.eat("RPAREN")
            return node

        if self.match("LBRACE"):
            return self.parse_map_lit()

        if self.match("LBRACK"):
            return self.parse_list_lit()

        if self.match("STRING"):
            return Literal(self.eat("STRING").value)

        if self.match("NUMBER"):
            txt = self.eat("NUMBER").value
            return Literal(float(txt) if "." in txt else int(txt))

        if self.match("BOOL"):
            return Literal(self.eat("BOOL").value == "true")

        if self.match("NULL"):
            self.eat("NULL")
            return Literal(None)

        if self.match("IDENT"):
            ident = self.eat("IDENT").value
            # call form: MOD . fn ⟨ args ⟩
            if self.match("DOT"):
                self.eat("DOT")
                fn = self.eat("IDENT").value
                args = self._parse_call_args()
                return Call(mod=ident, fn=fn, args=args)

            # call form: fn ⟨ args ⟩  (implicit GLOBAL)
            if self.match("GLYPH", GLYPH_PARAM_L):
                args = self._parse_call_args()
                return Call(mod="GLOBAL", fn=ident, args=args)

            return Var(ident)

        raise SyntaxError(f"Unexpected token {self.cur().kind}:{self.cur().value} @ {self.cur().pos}")

    def _parse_call_args(self) -> List[Node]:
        self.eat("GLYPH", GLYPH_PARAM_L)
        args: List[Node] = []
        if not self.match("GLYPH", GLYPH_PARAM_R):
            args.append(self.parse_expr())
            while self.match("GLYPH", GLYPH_SEP):
                self.eat("GLYPH", GLYPH_SEP)
                args.append(self.parse_expr())
        self.eat("GLYPH", GLYPH_PARAM_R)
        return args

    def parse_map_lit(self) -> MapLit:
        # JSON style: {"k":"v", "n": 1}
        # K style: {k⟶expr⋄x⟶expr}
        self.eat("LBRACE")
        items: List[Tuple[str, Node]] = []
        if self.match("RBRACE"):
            self.eat("RBRACE")
            return MapLit(items)

        while True:
            # key
            if self.match("STRING"):
                k = self.eat("STRING").value
            elif self.match("IDENT"):
                k = self.eat("IDENT").value
            else:
                raise SyntaxError(f"map key must be STRING or IDENT @ {self.cur().pos}")

            # sep ':' (GLYPH) หรือ '⟶'
            if self.match("GLYPH", GLYPH_ASSIGN):
                self.eat("GLYPH", GLYPH_ASSIGN)
            elif self.match("GLYPH", ":"):
                self.eat("GLYPH", ":")
            else:
                raise SyntaxError(f"map missing ':' or '⟶' after key {k!r} @ {self.cur().pos}")

            v = self.parse_expr()
            items.append((k, v))

            if self.match("COMMA"):
                self.eat("COMMA")
            elif self.match("GLYPH", GLYPH_SEP):
                self.eat("GLYPH", GLYPH_SEP)
            else:
                break

        self.eat("RBRACE")
        return MapLit(items)

    def parse_list_lit(self) -> ListLit:
        self.eat("LBRACK")
        items: List[Node] = []
        if self.match("RBRACK"):
            self.eat("RBRACK")
            return ListLit(items)

        items.append(self.parse_expr())
        while True:
            if self.match("COMMA"):
                self.eat("COMMA")
                items.append(self.parse_expr())
                continue
            if self.match("GLYPH", GLYPH_SEP):
                self.eat("GLYPH", GLYPH_SEP)
                items.append(self.parse_expr())
                continue
            break

        self.eat("RBRACK")
        return ListLit(items)


# ============================================================
# 5) BYTECODE
# ============================================================

@dataclass
class Instr:
    op: str
    a: Any = None
    b: Any = None


@dataclass
class FunctionBC:
    name: str
    code: List[Instr]
    locals_map: Dict[str, int]


@dataclass
class ModuleBC:
    name: str
    caps: List[str]
    functions: Dict[str, FunctionBC]


@dataclass
class BytecodeImage:
    entry: FunctionBC
    modules: Dict[str, ModuleBC]


class Compiler:
    def __init__(self):
        self.modules: Dict[str, ModuleBC] = {}

    def compile_program(self, prog: Program) -> BytecodeImage:
        if len(prog.stmts) == 1 and isinstance(prog.stmts[0], Entry):
            entry_block = prog.stmts[0].body
        else:
            entry_block = Block(prog.stmts)

        entry_fn = self._compile_function_body("__entry__", entry_block)
        return BytecodeImage(entry=entry_fn, modules=self.modules)

    def _compile_function_body(self, name: str, block: Block) -> FunctionBC:
        code: List[Instr] = []
        locals_map: Dict[str, int] = {}
        next_slot = 0

        def ensure_local(var: str) -> int:
            nonlocal next_slot
            if var not in locals_map:
                locals_map[var] = next_slot
                next_slot += 1
            return locals_map[var]

        def emit(op: str, a=None, b=None):
            code.append(Instr(op, a, b))

        def compile_expr(node: Node):
            if isinstance(node, Literal):
                v = node.value
                if v is None:
                    emit("PUSH_NULL")
                elif isinstance(v, bool):
                    emit("PUSH_B", 1 if v else 0)
                elif isinstance(v, (int, float)):
                    emit("PUSH_N", v)
                elif isinstance(v, str):
                    emit("PUSH_S", v)
                else:
                    emit("PUSH_S", str(v))
                return

            if isinstance(node, Var):
                slot = ensure_local(node.name)
                emit("LOAD", slot)
                return

            if isinstance(node, Unary):
                compile_expr(node.right)
                if node.op == "!":
                    emit("NOT")
                elif node.op == "-":
                    emit("NEG")
                else:
                    raise RuntimeError(f"Unknown unary {node.op}")
                return

            if isinstance(node, Binary):
                compile_expr(node.left)
                compile_expr(node.right)
                opmap = {
                    "+": "ADD",
                    "-": "SUB",
                    "*": "MUL",
                    "/": "DIV",
                    "==": "EQ",
                    "!=": "NE",
                    ">": "GT",
                    "<": "LT",
                    ">=": "GE",
                    "<=": "LE",
                    "&&": "AND",
                    "||": "OR",
                }
                emit(opmap[node.op])
                return

            if isinstance(node, MapLit):
                for k, v in node.items:
                    emit("PUSH_S", k)
                    compile_expr(v)
                emit("MAKE_MAP", len(node.items))
                return

            if isinstance(node, ListLit):
                for it in node.items:
                    compile_expr(it)
                emit("MAKE_LIST", len(node.items))
                return

            if isinstance(node, Call):
                for a in node.args:
                    compile_expr(a)
                emit("CALLM", node.mod, (node.fn, len(node.args)))
                return

            raise RuntimeError(f"Expr not supported: {node}")

        def compile_stmt(node: Node):
            if isinstance(node, Block):
                for s in node.stmts:
                    compile_stmt(s)
                return

            if isinstance(node, ModuleDecl):
                caps: List[str] = []
                if "cap" in node.params:
                    cap_val = self._const_eval(node.params["cap"])
                    if isinstance(cap_val, str):
                        caps = [c.strip() for c in cap_val.split(GLYPH_SEP) if c.strip()]
                mod = ModuleBC(name=node.name, caps=caps, functions={})
                self.modules[node.name] = mod
                init_fn = self._compile_function_body(f"{node.name}.__init__", node.body)
                mod.functions["__init__"] = init_fn
                emit("CALLM", node.name, ("__init__", 0))
                return

            if isinstance(node, FnDecl):
                mod = self.modules.get("GLOBAL")
                if not mod:
                    mod = ModuleBC(name="GLOBAL", caps=[], functions={})
                    self.modules["GLOBAL"] = mod
                fn_bc = self._compile_function_body(f"GLOBAL.{node.name}", node.body)
                mod.functions[node.name] = fn_bc
                return

            if isinstance(node, LetDecl):
                slot = ensure_local(node.name)
                compile_expr(node.expr)
                emit("STORE", slot)
                return

            if isinstance(node, Assign):
                slot = ensure_local(node.name)
                compile_expr(node.expr)
                emit("STORE", slot)
                return

            if isinstance(node, IfStmt):
                compile_expr(node.cond)
                jmpf_idx = len(code)
                emit("JMPF", None)
                compile_stmt(node.then_b)
                jmp_idx = len(code)
                emit("JMP", None)
                code[jmpf_idx].a = len(code)
                compile_stmt(node.else_b)
                code[jmp_idx].a = len(code)
                return

            if isinstance(node, LoopStmt):
                loop_start = len(code)
                compile_expr(node.cond)
                jmpf_idx = len(code)
                emit("JMPF", None)
                compile_stmt(node.body)
                emit("JMP", loop_start)
                code[jmpf_idx].a = len(code)
                return

            if isinstance(node, Emit):
                ns = self._const_eval(node.params.get("ns", Literal("IPC")))
                op = self._const_eval(node.params.get("op", Literal("EMIT")))
                args = node.params.get("args", MapLit([]))
                compile_expr(Literal(ns))
                compile_expr(Literal(op))
                compile_expr(args)
                emit("EMIT")
                return

            if isinstance(node, Listen):
                ns = self._const_eval(node.params.get("ns", Literal("IPC")))
                op = self._const_eval(node.params.get("op", Literal("LISTEN")))
                mode = self._const_eval(node.params.get("mode", Literal("block")))
                compile_expr(Literal(ns))
                compile_expr(Literal(op))
                compile_expr(Literal(mode))
                emit("LISTEN")
                return

            if isinstance(node, Return):
                compile_expr(node.expr)
                emit("RET")
                return

            if isinstance(node, ExprStmt):
                compile_expr(node.expr)
                emit("POP")
                return

            raise RuntimeError(f"Stmt not supported: {node}")

        compile_stmt(block)
        emit("PUSH_NULL")
        emit("RET")
        return FunctionBC(name=name, code=code, locals_map=locals_map)

    @staticmethod
    def _const_eval(node: Optional[Node]) -> Any:
        if node is None:
            return None
        if isinstance(node, Literal):
            return node.value
        return None


# ============================================================
# 6) PERSISTENT STORE (SQLite) สำหรับ CMD memory
# ============================================================

class CommandStore:
    def __init__(self, db_path: str | Path = "kfast.db"):
        self.db_path = Path(db_path)
        self._lock = threading.RLock()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=NORMAL;")
        con.execute("PRAGMA foreign_keys=ON;")
        return con

    def _init_db(self) -> None:
        with self._lock, self._conn() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS commands(
                    name TEXT PRIMARY KEY,
                    src  TEXT NOT NULL,
                    updated REAL NOT NULL
                )
                """
            )

    def save(self, name: str, src: str) -> None:
        ts = time.time()
        with self._lock, self._conn() as con:
            con.execute(
                """
                INSERT INTO commands(name, src, updated)
                VALUES(?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    src=excluded.src,
                    updated=excluded.updated
                """,
                (name, src, ts),
            )

    def load(self, name: str) -> Optional[str]:
        with self._lock, self._conn() as con:
            row = con.execute("SELECT src FROM commands WHERE name=?", (name,)).fetchone()
            return row[0] if row else None

    def delete(self, name: str) -> bool:
        with self._lock, self._conn() as con:
            cur = con.execute("DELETE FROM commands WHERE name=?", (name,))
            return cur.rowcount > 0

    def list(self, prefix: Optional[str] = None) -> List[str]:
        with self._lock, self._conn() as con:
            if prefix:
                rows = con.execute(
                    "SELECT name FROM commands WHERE name LIKE ? ORDER BY name ASC",
                    (prefix + "%",),
                ).fetchall()
            else:
                rows = con.execute("SELECT name FROM commands ORDER BY name ASC").fetchall()
            return [r[0] for r in rows]


# ============================================================
# 7) KERNEL RUNTIME
# ============================================================

class KernelRuntime:
    def __init__(self, store: Optional[CommandStore] = None):
        self.mem: Dict[int, bytearray] = {}
        self.next_handle = 1
        self.procs: Dict[int, Dict[str, Any]] = {}
        self.next_pid = 1
        self.signal_queue: List[Dict[str, Any]] = []
        self.store = store or CommandStore()

    def syscall(self, caps: List[str], ns: str, op: str, args: Dict[str, Any]) -> Any:
        ns = ns.upper()
        op = op.upper()

        # Capability guard (เบา: เช็คแบบง่าย)
        if ns not in caps and ns not in ("SYS", "IPC"):
            raise PermissionError(f"CAP DENIED: need {ns} in caps={caps}")

        if ns == "SYS":
            return self._sys(op, args)
        if ns == "MEM":
            return self._mem(op, args)
        if ns == "PROC":
            return self._proc(op, args)
        if ns == "IPC":
            return self._ipc(op, args)
        if ns == "CMD":
            return self._cmd(op, args)

        return {"ok": False, "ns": ns, "op": op, "err": "UNIMPLEMENTED"}

    def _sys(self, op: str, args: Dict[str, Any]) -> Any:
        if op == "INIT":
            return {"ok": True, "mode": args.get("mode", "SDA")}
        if op == "HALT":
            return {"ok": True, "halt": True}
        if op == "TIME":
            return {"unix": int(time.time())}
        if op == "LOG":
            level = args.get("level", "INFO")
            msg = args.get("msg", "")
            print(f"[SYS.LOG/{level}] {msg}")
            return {"ok": True}
        return {"ok": False, "err": "SYS_UNKNOWN_OP", "op": op}

    def _mem(self, op: str, args: Dict[str, Any]) -> Any:
        if op == "ALLOC":
            size = int(args.get("size", 0))
            if size <= 0:
                return {"ok": False, "err": "SIZE_INVALID"}
            h = self.next_handle
            self.next_handle += 1
            self.mem[h] = bytearray(size)
            return {"ok": True, "handle": h, "size": size}
        if op == "FREE":
            h = int(args.get("handle", 0))
            self.mem.pop(h, None)
            return {"ok": True}
        return {"ok": False, "err": "MEM_UNKNOWN_OP", "op": op}

    def _proc(self, op: str, args: Dict[str, Any]) -> Any:
        if op == "SPAWN":
            pid = self.next_pid
            self.next_pid += 1
            self.procs[pid] = {
                "name": args.get("name", f"PROC{pid}"),
                "prio": args.get("prio", "NORMAL"),
                "state": "READY",
            }
            return {"ok": True, "pid": pid}
        if op == "KILL":
            pid = int(args.get("pid", 0))
            self.procs.pop(pid, None)
            return {"ok": True}
        if op == "YIELD":
            return {"ok": True}
        if op == "STATUS":
            pid = int(args.get("pid", 0))
            return {"ok": True, "proc": self.procs.get(pid)}
        return {"ok": False, "err": "PROC_UNKNOWN_OP", "op": op}

    def _ipc(self, op: str, args: Dict[str, Any]) -> Any:
        if op == "EMIT":
            sig = {"ch": args.get("ch", "DEFAULT"), "data": args.get("data")}
            self.signal_queue.append(sig)
            return {"ok": True}
        if op == "LISTEN":
            ch = args.get("ch", "DEFAULT")
            for i, s in enumerate(self.signal_queue):
                if s.get("ch") == ch:
                    return self.signal_queue.pop(i)
            return None
        return {"ok": False, "err": "IPC_UNKNOWN_OP", "op": op}

    def _cmd(self, op: str, args: Dict[str, Any]) -> Any:
        # persistence only (RUN ทำใน VM)
        if op == "SAVE":
            name = str(args.get("name", ""))
            src = str(args.get("src", ""))
            if not name:
                return {"ok": False, "err": "NAME_REQUIRED"}
            self.store.save(name, src)
            return {"ok": True}
        if op == "LOAD":
            name = str(args.get("name", ""))
            src = self.store.load(name)
            return {"ok": bool(src is not None), "src": src}
        if op == "LIST":
            prefix = args.get("prefix")
            names = self.store.list(str(prefix) if prefix else None)
            return {"ok": True, "names": names}
        if op == "DEL":
            name = str(args.get("name", ""))
            return {"ok": self.store.delete(name)}
        return {"ok": False, "err": "CMD_UNKNOWN_OP", "op": op}


# ============================================================
# 8) VM
# ============================================================

class VM:
    def __init__(self, image: BytecodeImage, kernel: KernelRuntime, *, entry_caps: Optional[List[str]] = None):
        self.image = image
        self.kernel = kernel
        self.stack: List[Any] = []
        self.frames: List[Tuple[FunctionBC, int, List[Any], List[str]]] = []
        # ให้ entry ใช้ SYS/IPC/CMD ได้เลย (เพื่องานจำคำสั่ง)
        self.entry_caps = entry_caps or ["SYS", "IPC", "CMD", "MEM", "PROC"]

    def run(self) -> Any:
        return self._call_fn(self.image.entry, [], self.entry_caps)

    def _call_fn(self, fn: FunctionBC, args: List[Any], caps: List[str]) -> Any:
        locals_arr = [None] * (max(fn.locals_map.values(), default=-1) + 1)
        ip = 0
        self.frames.append((fn, ip, locals_arr, caps))
        while self.frames:
            fn, ip, locals_arr, caps = self.frames[-1]
            if ip >= len(fn.code):
                self.frames.pop()
                return None
            ins = fn.code[ip]
            self.frames[-1] = (fn, ip + 1, locals_arr, caps)
            r = self._exec(ins, fn, locals_arr, caps)
            if r == "__RET__":
                val = self.stack.pop() if self.stack else None
                self.frames.pop()
                if not self.frames:
                    return val
                self.stack.append(val)
        return None

    def _set_ip(self, addr: int):
        fn, _, locals_arr, caps = self.frames[-1]
        self.frames[-1] = (fn, int(addr), locals_arr, caps)

    def _push_frame(self, fn: FunctionBC, caps: List[str]):
        locals_arr = [None] * (max(fn.locals_map.values(), default=-1) + 1)
        self.frames.append((fn, 0, locals_arr, caps))

    def _exec(self, ins: Instr, fn: FunctionBC, locals_arr: List[Any], caps: List[str]) -> Any:
        op = ins.op

        if op == "PUSH_N":
            self.stack.append(ins.a)
            return None
        if op == "PUSH_S":
            self.stack.append(ins.a)
            return None
        if op == "PUSH_B":
            self.stack.append(bool(ins.a))
            return None
        if op == "PUSH_NULL":
            self.stack.append(None)
            return None
        if op == "LOAD":
            self.stack.append(locals_arr[ins.a])
            return None
        if op == "STORE":
            locals_arr[ins.a] = self.stack.pop()
            return None
        if op == "POP":
            self.stack.pop()
            return None

        if op in ("ADD", "SUB", "MUL", "DIV", "EQ", "NE", "GT", "LT", "GE", "LE", "AND", "OR"):
            b = self.stack.pop()
            a = self.stack.pop()
            if op == "ADD":
                if isinstance(a, str) or isinstance(b, str):
                    self.stack.append(str(a) + str(b))
                else:
                    self.stack.append(a + b)
            elif op == "SUB":
                self.stack.append(a - b)
            elif op == "MUL":
                self.stack.append(a * b)
            elif op == "DIV":
                self.stack.append(a / b)
            elif op == "EQ":
                self.stack.append(a == b)
            elif op == "NE":
                self.stack.append(a != b)
            elif op == "GT":
                self.stack.append(a > b)
            elif op == "LT":
                self.stack.append(a < b)
            elif op == "GE":
                self.stack.append(a >= b)
            elif op == "LE":
                self.stack.append(a <= b)
            elif op == "AND":
                self.stack.append(bool(a) and bool(b))
            elif op == "OR":
                self.stack.append(bool(a) or bool(b))
            return None

        if op == "NOT":
            a = self.stack.pop()
            self.stack.append(not bool(a))
            return None

        if op == "NEG":
            a = self.stack.pop()
            self.stack.append(-a)
            return None

        if op == "JMP":
            self._set_ip(ins.a)
            return None

        if op == "JMPF":
            cond = self.stack.pop()
            if not bool(cond):
                self._set_ip(ins.a)
            return None

        if op == "RET":
            return "__RET__"

        if op == "MAKE_MAP":
            n = int(ins.a)
            d: Dict[str, Any] = {}
            for _ in range(n):
                val = self.stack.pop()
                key = self.stack.pop()
                d[str(key)] = val
            self.stack.append(d)
            return None

        if op == "MAKE_LIST":
            n = int(ins.a)
            items = [self.stack.pop() for _ in range(n)][::-1]
            self.stack.append(items)
            return None

        if op == "CALLM":
            modname = ins.a
            fnname, argc = ins.b
            args = [self.stack.pop() for _ in range(argc)][::-1]

            mod = self.image.modules.get(modname)
            if not mod:
                return self._builtin_call(modname, fnname, args, caps)

            mod_caps = list(set(mod.caps + ["SYS", "IPC", "CMD"]))
            f = mod.functions.get(fnname)
            if not f:
                return self._builtin_call(modname, fnname, args, mod_caps)

            self._push_frame(f, mod_caps)
            return None

        if op == "EMIT":
            args_map = self.stack.pop()
            sop = self.stack.pop()
            sns = self.stack.pop()
            if not isinstance(args_map, dict):
                raise TypeError("EMIT expects args as map/dict")
            rv = self.kernel.syscall(caps, str(sns), str(sop), args_map)
            self.stack.append(rv)
            return None

        if op == "LISTEN":
            mode = self.stack.pop()
            sop = self.stack.pop()
            sns = self.stack.pop()
            rv = self.kernel.syscall(caps, str(sns), str(sop), {"mode": mode})
            self.stack.append(rv)
            return None

        raise RuntimeError(f"Unknown opcode: {op}")

    # ---- Built-in module mapping (thin stdlib) ----
    def _builtin_call(self, mod: str, fn: str, args: List[Any], caps: List[str]):
        # LOG.ส่ง(level,msg) -> SYS.LOG
        if mod == "LOG" and fn == "ส่ง":
            level = args[0] if len(args) > 0 else "INFO"
            msg = args[1] if len(args) > 1 else ""
            rv = self.kernel.syscall(caps, "SYS", "LOG", {"level": level, "msg": msg})
            self.stack.append(rv)
            return None

        # SYS.เริ่ม(mode) -> SYS.INIT
        if mod == "SYS" and fn in ("เริ่ม", "INIT"):
            mode = args[0] if args else "SDA"
            rv = self.kernel.syscall(caps, "SYS", "INIT", {"mode": mode})
            self.stack.append(rv)
            return None

        # MEM.จอง(size) -> MEM.ALLOC
        if mod == "MEM" and fn in ("จอง", "ALLOC"):
            size = int(args[0]) if args else 0
            rv = self.kernel.syscall(caps, "MEM", "ALLOC", {"size": size})
            self.stack.append(rv)
            return None

        # PROC.สร้าง(name,prio) -> PROC.SPAWN
        if mod == "PROC" and fn in ("สร้าง", "SPAWN"):
            name = args[0] if len(args) > 0 else "PROC"
            prio = args[1] if len(args) > 1 else "NORMAL"
            rv = self.kernel.syscall(caps, "PROC", "SPAWN", {"name": name, "prio": prio})
            self.stack.append(rv)
            return None

        # ---- CMD: persistent command memory ----
        if mod == "CMD" and fn in ("จำ", "SAVE"):
            name = str(args[0]) if len(args) > 0 else ""
            src = str(args[1]) if len(args) > 1 else ""
            rv = self.kernel.syscall(caps, "CMD", "SAVE", {"name": name, "src": src})
            self.stack.append(rv)
            return None

        if mod == "CMD" and fn in ("ดู", "LOAD"):
            name = str(args[0]) if args else ""
            rv = self.kernel.syscall(caps, "CMD", "LOAD", {"name": name})
            self.stack.append(rv.get("src"))
            return None

        if mod == "CMD" and fn in ("รายการ", "LIST"):
            prefix = str(args[0]) if args else None
            rv = self.kernel.syscall(caps, "CMD", "LIST", {"prefix": prefix} if prefix else {})
            self.stack.append(rv.get("names", []))
            return None

        if mod == "CMD" and fn in ("ลืม", "DEL"):
            name = str(args[0]) if args else ""
            rv = self.kernel.syscall(caps, "CMD", "DEL", {"name": name})
            self.stack.append(rv)
            return None

        if mod == "CMD" and fn in ("จำไฟล์", "SAVEFILE"):
            name = str(args[0]) if len(args) > 0 else ""
            path = str(args[1]) if len(args) > 1 else ""
            src = Path(path).read_text(encoding="utf-8")
            rv = self.kernel.syscall(caps, "CMD", "SAVE", {"name": name, "src": src})
            self.stack.append(rv)
            return None

        if mod == "CMD" and fn in ("ส่งออก", "EXPORT"):
            name = str(args[0]) if len(args) > 0 else ""
            path = str(args[1]) if len(args) > 1 else ""
            rv = self.kernel.syscall(caps, "CMD", "LOAD", {"name": name})
            src = rv.get("src")
            if src is None:
                self.stack.append({"ok": False, "err": "NOT_FOUND"})
            else:
                Path(path).write_text(str(src), encoding="utf-8")
                self.stack.append({"ok": True})
            return None

        if mod == "CMD" and fn in ("ทำ", "RUN"):
            name = str(args[0]) if args else ""
            # load source แล้ว compile/run ด้วย kernel เดิม
            rv = self.kernel.syscall(caps, "CMD", "LOAD", {"name": name})
            src = rv.get("src")
            if src is None:
                self.stack.append(None)
                return None
            result = compile_and_run(str(src), kernel=self.kernel)
            self.stack.append(result)
            return None

        # fallback: ส่งเป็น IPC.EMIT
        rv = self.kernel.syscall(caps, "IPC", "EMIT", {"ch": f"{mod}.{fn}", "data": args})
        self.stack.append(rv)
        return None


# ============================================================
# 9) PIPELINE HELPERS
# ============================================================


def compile_src(src: str) -> BytecodeImage:
    tokens = lex(src)
    ast_prog = Parser(tokens).parse_program()
    bc = Compiler().compile_program(ast_prog)
    return bc


def compile_and_run(src: str, *, kernel: Optional[KernelRuntime] = None) -> Any:
    bc = compile_src(src)
    kern = kernel or KernelRuntime()
    vm = VM(bc, kern)
    return vm.run()


def run_file(path: str, *, kernel: Optional[KernelRuntime] = None) -> Any:
    src = Path(path).read_text(encoding="utf-8")
    return compile_and_run(src, kernel=kernel)


# ============================================================
# 10) CLI
# ============================================================


def _cmd_save(store: CommandStore, name: str, file_path: str) -> None:
    src = Path(file_path).read_text(encoding="utf-8")
    store.save(name, src)


def _cmd_run(kernel: KernelRuntime, name: str) -> Any:
    src = kernel.store.load(name)
    if src is None:
        raise SystemExit(f"ไม่พบคำสั่งที่จำไว้: {name}")
    return compile_and_run(src, kernel=kernel)


def main(argv: Optional[List[str]] = None) -> None:
    argv = list(argv or sys.argv[1:])

    if not argv:
        print("usage:")
        print("  python3 kfast_system.py run <file.kap>")
        print("  python3 kfast_system.py cmd save <name> <file.kap>")
        print("  python3 kfast_system.py cmd run  <name>")
        print("  python3 kfast_system.py cmd list")
        print("  python3 kfast_system.py cmd show <name>")
        print("  python3 kfast_system.py cmd del  <name>")
        sys.exit(0)

    # shared kernel/store for this process
    kernel = KernelRuntime(store=CommandStore())

    if argv[0] == "run":
        if len(argv) < 2:
            raise SystemExit("run ต้องระบุไฟล์ .kap")
        rv = run_file(argv[1], kernel=kernel)
        print("[RESULT]", rv)
        return

    if argv[0] == "cmd":
        if len(argv) < 2:
            raise SystemExit("cmd ต้องมี subcommand")
        sub = argv[1]

        if sub == "save":
            if len(argv) != 4:
                raise SystemExit("cmd save <name> <file.kap>")
            _cmd_save(kernel.store, argv[2], argv[3])
            print("OK")
            return

        if sub == "run":
            if len(argv) != 3:
                raise SystemExit("cmd run <name>")
            rv = _cmd_run(kernel, argv[2])
            print("[RESULT]", rv)
            return

        if sub == "list":
            names = kernel.store.list()
            print("\n".join(names))
            return

        if sub == "show":
            if len(argv) != 3:
                raise SystemExit("cmd show <name>")
            src = kernel.store.load(argv[2])
            if src is None:
                raise SystemExit("NOT_FOUND")
            print(src)
            return

        if sub == "del":
            if len(argv) != 3:
                raise SystemExit("cmd del <name>")
            ok = kernel.store.delete(argv[2])
            print("OK" if ok else "NOT_FOUND")
            return

        raise SystemExit(f"ไม่รู้จัก cmd subcommand: {sub}")

    # convenience: ถ้า arg แรกเป็นไฟล์ .kap ให้รันทันที
    if len(argv) == 1 and (argv[0].endswith(".kap") and Path(argv[0]).exists()):
        rv = run_file(argv[0], kernel=kernel)
        print("[RESULT]", rv)
        return

    raise SystemExit(f"ไม่รู้จักคำสั่ง: {' '.join(argv)}")


if __name__ == "__main__":
    main()
