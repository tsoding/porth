#!/usr/bin/env python3

import os
import sys
import subprocess
import shlex
from os import path
from typing import *
from enum import Enum, auto
from dataclasses import dataclass

debug=False

Loc=Tuple[str, int, int]

# TODO: include operation documentation into the porth script itself
# also make a subcommand that generates the language reference from that documentation
class OpType(Enum):
    PUSH_INT=auto()
    PUSH_STR=auto()
    PLUS=auto()
    MINUS=auto()
    MOD=auto()
    EQ=auto()
    GT=auto()
    LT=auto()
    GE=auto()
    LE=auto()
    NE=auto()
    SHR=auto()
    SHL=auto()
    BOR=auto()
    BAND=auto()
    PRINT=auto()
    IF=auto()
    END=auto()
    ELSE=auto()
    DUP=auto()
    DUP2=auto()
    SWAP=auto()
    DROP=auto()
    OVER=auto()
    WHILE=auto()
    DO=auto()
    MEM=auto()
    # TODO: implement typing for load/store operations
    LOAD=auto()
    STORE=auto()
    SYSCALL0=auto()
    SYSCALL1=auto()
    SYSCALL2=auto()
    SYSCALL3=auto()
    SYSCALL4=auto()
    SYSCALL5=auto()
    SYSCALL6=auto()

@dataclass
class Op:
    typ: OpType
    loc: Loc
    # Exists only for OpType.PUSH_INT, Op.PUSH_STR. Contains the value
    # that needs to be pushed onto the stack.
    value: Optional[Union[int, str]] = None
    # Exists only for block Ops like `if`, `else`, `while`,
    # etc. Contains an index of an Op within the Program that the
    # execution has to jump to depending on the circumstantces. In
    # case of `if` it's the place of else branch, in case of `else`
    # it's the end of the construction, etc.
    jmp: Optional[int] = None

Program=List[Op]

class TokenType(Enum):
    WORD=auto()
    INT=auto()
    STR=auto()

@dataclass
class Token:
    typ: TokenType
    loc: Loc
    value: Union[int, str]

STR_CAPACITY = 640_000 # should be enough for everyone
MEM_CAPACITY = 640_000

def simulate_little_endian_linux(program: Program):
    stack = []
    mem = bytearray(STR_CAPACITY + MEM_CAPACITY)
    str_offsets = {}
    str_size = 0
    ip = 0
    while ip < len(program):
        assert len(OpType) == 36, "Exhaustive op handling in simulate_little_endian_linux"
        op = program[ip]
        if op.typ == OpType.PUSH_INT:
            assert op.value is not None, "This could be a bug in the compilation step"
            stack.append(op.value)
            ip += 1
        elif op.typ == OpType.PUSH_STR:
            assert op.value is not None, "This could be a bug in the compilation step"
            bs = bytes(op.value, 'utf-8')
            n = len(bs)
            stack.append(n)
            if ip not in str_offsets:
                str_offsets[ip] = str_size
                mem[str_size:str_size+n] = bs
                str_size += n
                assert str_size <= STR_CAPACITY, "String buffer overflow"
            stack.append(str_offsets[ip])
            ip += 1
        elif op.typ == OpType.PLUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
            ip += 1
        elif op.typ == OpType.MINUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(b - a)
            ip += 1
        elif op.typ == OpType.MOD:
            a = stack.pop()
            b = stack.pop()
            stack.append(b % a)
            ip += 1
        elif op.typ == OpType.EQ:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a == b))
            ip += 1
        elif op.typ == OpType.GT:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b > a))
            ip += 1
        elif op.typ == OpType.LT:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b < a))
            ip += 1
        elif op.typ == OpType.GE:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b >= a))
            ip += 1
        elif op.typ == OpType.LE:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b <= a))
            ip += 1
        elif op.typ == OpType.NE:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b != a))
            ip += 1
        elif op.typ == OpType.SHR:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b >> a))
            ip += 1
        elif op.typ == OpType.SHL:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(b << a))
            ip += 1
        elif op.typ == OpType.BOR:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a | b))
            ip += 1
        elif op.typ == OpType.BAND:
            a = stack.pop()
            b = stack.pop()
            stack.append(int(a & b))
            ip += 1
        elif op.typ == OpType.IF:
            a = stack.pop()
            if a == 0:
                assert op.jmp is not None, "This could be a bug in the compilation step"
                ip = op.jmp
            else:
                ip += 1
        elif op.typ == OpType.ELSE:
            assert op.jmp is not None, "This could be a bug in the compilation step"
            ip = op.jmp
        elif op.typ == OpType.END:
            assert op.jmp is not None, "This could be a bug in the compilation step"
            ip = op.jmp
        elif op.typ == OpType.PRINT:
            a = stack.pop()
            print(a)
            ip += 1
        elif op.typ == OpType.DUP:
            a = stack.pop()
            stack.append(a)
            stack.append(a)
            ip += 1
        elif op.typ == OpType.DUP2:
            b = stack.pop()
            a = stack.pop()
            stack.append(a)
            stack.append(b)
            stack.append(a)
            stack.append(b)
            ip += 1
        elif op.typ == OpType.SWAP:
            a = stack.pop()
            b = stack.pop()
            stack.append(a)
            stack.append(b)
            ip += 1
        elif op.typ == OpType.DROP:
            stack.pop()
            ip += 1
        elif op.typ == OpType.OVER:
            a = stack.pop()
            b = stack.pop()
            stack.append(b)
            stack.append(a)
            stack.append(b)
            ip += 1
        elif op.typ == OpType.WHILE:
            ip += 1
        elif op.typ == OpType.DO:
            a = stack.pop()
            if a == 0:
                assert op.jmp is not None, "This could be a bug in the compilation step"
                ip = op.jmp
            else:
                ip += 1
        elif op.typ == OpType.MEM:
            stack.append(STR_CAPACITY)
            ip += 1
        elif op.typ == OpType.LOAD:
            addr = stack.pop()
            byte = mem[addr]
            stack.append(byte)
            ip += 1
        elif op.typ == OpType.STORE:
            value = stack.pop()
            addr = stack.pop()
            mem[addr] = value & 0xFF
            ip += 1
        elif op.typ == OpType.SYSCALL0:
            syscall_number = stack.pop()
            if syscall_number == 39:
                stack.append(os.getpid())
            else:
                assert False, "unknown syscall number %d" % syscall_number
            ip += 1
        elif op.typ == OpType.SYSCALL1:
            assert False, "not implemented"
        elif op.typ == OpType.SYSCALL2:
            assert False, "not implemented"
        elif op.typ == OpType.SYSCALL3:
            syscall_number = stack.pop()
            arg1 = stack.pop()
            arg2 = stack.pop()
            arg3 = stack.pop()
            if syscall_number == 1:
                fd = arg1
                buf = arg2
                count = arg3
                s = mem[buf:buf+count].decode('utf-8')
                if fd == 1:
                    print(s, end='')
                elif fd == 2:
                    print(s, end='', file=sys.stderr)
                else:
                    assert False, "unknown file descriptor %d" % fd
                stack.append(count)
            else:
                assert False, "unknown syscall number %d" % syscall_number
            ip += 1
        elif op.typ == OpType.SYSCALL4:
            assert False, "not implemented"
        elif op.typ == OpType.SYSCALL5:
            assert False, "not implemented"
        elif op.typ == OpType.SYSCALL6:
            assert False, "not implemented"
        else:
            assert False, "unreachable"
    if debug:
        print("[INFO] Memory dump")
        print(mem[:20])

def generate_nasm_linux_x86_64(program: Program, out_file_path: str):
    strs = []
    with open(out_file_path, "w") as out:
        out.write("BITS 64\n")
        out.write("segment .text\n")
        out.write("print:\n")
        out.write("    mov     r9, -3689348814741910323\n")
        out.write("    sub     rsp, 40\n")
        out.write("    mov     BYTE [rsp+31], 10\n")
        out.write("    lea     rcx, [rsp+30]\n")
        out.write(".L2:\n")
        out.write("    mov     rax, rdi\n")
        out.write("    lea     r8, [rsp+32]\n")
        out.write("    mul     r9\n")
        out.write("    mov     rax, rdi\n")
        out.write("    sub     r8, rcx\n")
        out.write("    shr     rdx, 3\n")
        out.write("    lea     rsi, [rdx+rdx*4]\n")
        out.write("    add     rsi, rsi\n")
        out.write("    sub     rax, rsi\n")
        out.write("    add     eax, 48\n")
        out.write("    mov     BYTE [rcx], al\n")
        out.write("    mov     rax, rdi\n")
        out.write("    mov     rdi, rdx\n")
        out.write("    mov     rdx, rcx\n")
        out.write("    sub     rcx, 1\n")
        out.write("    cmp     rax, 9\n")
        out.write("    ja      .L2\n")
        out.write("    lea     rax, [rsp+32]\n")
        out.write("    mov     edi, 1\n")
        out.write("    sub     rdx, rax\n")
        out.write("    xor     eax, eax\n")
        out.write("    lea     rsi, [rsp+32+rdx]\n")
        out.write("    mov     rdx, r8\n")
        out.write("    mov     rax, 1\n")
        out.write("    syscall\n")
        out.write("    add     rsp, 40\n")
        out.write("    ret\n")
        out.write("global _start\n")
        out.write("_start:\n")
        for ip in range(len(program)):
            op = program[ip]
            assert len(OpType) == 36, "Exhaustive ops handling in generate_nasm_linux_x86_64"
            if op.typ == OpType.PUSH_INT:
                assert op.value is not None, "This could be a bug in the compilation step"
                out.write("    ;; -- push int %d --\n" % op.value)
                out.write("    mov rax, %d\n" % op.value)
                out.write("    push rax\n")
            elif op.typ == OpType.PUSH_STR:
                assert op.value is not None, "This could be a bug in the compilation step"
                out.write("    ;; -- push str --\n")
                out.write("    mov rax, %d\n" % len(op.value))
                out.write("    push rax\n")
                out.write("    push str_%d\n" % len(strs))
                strs.append(op.value)
            elif op.typ == OpType.PLUS:
                out.write("    ;; -- plus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    add rax, rbx\n")
                out.write("    push rax\n")
            elif op.typ == OpType.MINUS:
                out.write("    ;; -- minus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    sub rbx, rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.MOD:
                out.write("    ;; -- mod --\n")
                out.write("    xor rdx, rdx\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    div rbx\n")
                out.write("    push rdx\n");
            elif op.typ == OpType.SHR:
                out.write("    ;; -- shr --\n")
                out.write("    pop rcx\n")
                out.write("    pop rbx\n")
                out.write("    shr rbx, cl\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.SHL:
                out.write("    ;; -- shl --\n")
                out.write("    pop rcx\n")
                out.write("    pop rbx\n")
                out.write("    shl rbx, cl\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.BOR:
                out.write("    ;; -- bor --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    or rbx, rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.BAND:
                out.write("    ;; -- band --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    and rbx, rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.PRINT:
                out.write("    ;; -- print --\n")
                out.write("    pop rdi\n")
                out.write("    call print\n")
            elif op.typ == OpType.EQ:
                out.write("    ;; -- equal -- \n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rax\n");
                out.write("    pop rbx\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmove rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.GT:
                out.write("    ;; -- gt --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovg rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.LT:
                out.write("    ;; -- gt --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovl rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.GE:
                out.write("    ;; -- gt --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovge rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.LE:
                out.write("    ;; -- gt --\n")
                out.write("    mov rcx, 0\n");
                out.write("    mov rdx, 1\n");
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    cmp rax, rbx\n");
                out.write("    cmovle rcx, rdx\n");
                out.write("    push rcx\n")
            elif op.typ == OpType.NE:
                out.write("    ;; -- ne --\n")
                out.write("    mov rcx, 0\n")
                out.write("    mov rdx, 1\n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    cmp rax, rbx\n")
                out.write("    cmovne rcx, rdx\n")
                out.write("    push rcx\n")
            elif op.typ == OpType.IF:
                out.write("    ;; -- if --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert op.jmp is not None, "This could be a bug in the compilation step"
                out.write("    jz addr_%d\n" % op.jmp)
            elif op.typ == OpType.ELSE:
                out.write("    ;; -- else --\n")
                assert op.jmp is not None, "This could be a bug in the compilation step"
                out.write("    jmp addr_%d\n" % op.jmp)
                # on `0` the `if` instruction jumps to the one that follows `else`.
                out.write("addr_%d:\n" % (ip + 1)) 
            elif op.typ == OpType.END:
                assert op.jmp is not None, "This could be a bug in the compilation step"
                out.write("addr_%d:\n" % ip)
                out.write("    ;; -- end --\n")
                if ip + 1 != op.jmp:
                    out.write("    jmp addr_%d\n" % op.jmp)
                out.write("addr_%d:\n" % (ip + 1))
            elif op.typ == OpType.DUP:
                out.write("    ;; -- dup -- \n")
                out.write("    pop rax\n")
                out.write("    push rax\n")
                out.write("    push rax\n")
            elif op.typ == OpType.DUP2:
                out.write("    ;; -- 2dup -- \n")
                out.write("    pop rbx\n")
                out.write("    pop rax\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.SWAP:
                out.write("    ;; -- swap --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.DROP:
                out.write("    ;; -- drop --\n")
                out.write("    pop rax\n")
            elif op.typ == OpType.OVER:
                out.write("    ;; -- over --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    push rbx\n")
                out.write("    push rax\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.WHILE:
                out.write("    ;; -- while --\n")
                out.write("addr_%d:\n" % ip)
            elif op.typ == OpType.DO:
                out.write("    ;; -- do --\n")
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert op.jmp is not None, "This could be a bug in the compilation step"
                out.write("    jz addr_%d\n" % op.jmp)
            elif op.typ == OpType.MEM:
                out.write("    ;; -- mem --\n")
                out.write("    push mem\n")
            elif op.typ == OpType.LOAD:
                out.write("    ;; -- load --\n")
                out.write("    pop rax\n")
                out.write("    xor rbx, rbx\n")
                out.write("    mov bl, [rax]\n")
                out.write("    push rbx\n")
            elif op.typ == OpType.STORE:
                out.write("    ;; -- store --\n")
                out.write("    pop rbx\n");
                out.write("    pop rax\n");
                out.write("    mov [rax], bl\n");
            elif op.typ == OpType.SYSCALL0:
                out.write("    ;; -- syscall0 --\n")
                out.write("    pop rax\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL1:
                out.write("    ;; -- syscall1 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL2:
                out.write("    ;; -- syscall2 -- \n")
                out.write("    pop rax\n");
                out.write("    pop rdi\n");
                out.write("    pop rsi\n");
                out.write("    syscall\n");
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL3:
                out.write("    ;; -- syscall3 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL4:
                out.write("    ;; -- syscall4 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL5:
                out.write("    ;; -- syscall5 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    pop r8\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            elif op.typ == OpType.SYSCALL6:
                out.write("    ;; -- syscall6 --\n")
                out.write("    pop rax\n")
                out.write("    pop rdi\n")
                out.write("    pop rsi\n")
                out.write("    pop rdx\n")
                out.write("    pop r10\n")
                out.write("    pop r8\n")
                out.write("    pop r9\n")
                out.write("    syscall\n")
                out.write("    push rax\n")
            else:
                assert False, "unreachable"

        out.write("addr_%d:\n" % len(program))
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")
        out.write("segment .data\n")
        for index, s in enumerate(strs):
            out.write("str_%d: db %s\n" % (index, ','.join(map(hex, list(bytes(s, 'utf-8'))))))
        out.write("segment .bss\n")
        out.write("mem: resb %d\n" % MEM_CAPACITY)

assert len(OpType) == 36, "Exhaustive BUILTIN_WORDS definition. Keep in mind that not all of the new ops need to be defined in here. Only those that introduce new builtin words."
BUILTIN_WORDS = {
    '+': OpType.PLUS,
    '-': OpType.MINUS,
    'mod': OpType.MOD,
    'print': OpType.PRINT,
    '=': OpType.EQ,
    '>': OpType.GT,
    '<': OpType.LT,
    '>=': OpType.GE,
    '<=': OpType.LE,
    '!=': OpType.NE,
    'shr': OpType.SHR,
    'shl': OpType.SHL,
    'bor': OpType.BOR,
    'band': OpType.BAND,
    'if': OpType.IF,
    'end': OpType.END,
    'else': OpType.ELSE,
    'dup': OpType.DUP,
    '2dup': OpType.DUP2,
    'swap': OpType.SWAP,
    'drop': OpType.DROP,
    'over': OpType.OVER,
    'while': OpType.WHILE,
    'do': OpType.DO,
    'mem': OpType.MEM,
    '.': OpType.STORE,
    ',': OpType.LOAD,
    'syscall0': OpType.SYSCALL0,
    'syscall1': OpType.SYSCALL1,
    'syscall2': OpType.SYSCALL2,
    'syscall3': OpType.SYSCALL3,
    'syscall4': OpType.SYSCALL4,
    'syscall5': OpType.SYSCALL5,
    'syscall6': OpType.SYSCALL6,
}

def compile_token_to_op(token: Token) -> Op:
    assert len(TokenType) == 3, "Exhaustive token handling in compile_token_to_op"
    if token.typ == TokenType.WORD:
        if token.value in BUILTIN_WORDS:
            return Op(typ=BUILTIN_WORDS[token.value], loc=token.loc)
        else:
            print("%s:%d:%d: unknown word `%s`" % (token.loc + (token.value, )))
            exit(1)
    elif token.typ == TokenType.INT:
        return Op(typ=OpType.PUSH_INT, value=token.value, loc=token.loc)
    elif token.typ == TokenType.STR:
        return Op(typ=OpType.PUSH_STR, value=token.value, loc=token.loc)
    else:
        assert False, 'unreachable'

def compile_tokens_to_program(tokens: List[Token]) -> Program:
    stack = []
    program = [compile_token_to_op(token) for token in tokens]
    for ip in range(len(program)):
        op = program[ip]
        assert len(OpType) == 36, "Exhaustive ops handling in compile_tokens_to_program. Keep in mind that not all of the ops need to be handled in here. Only those that form blocks."
        if op.typ == OpType.IF:
            stack.append(ip)
        elif op.typ == OpType.ELSE:
            if_ip = stack.pop()
            if program[if_ip].typ != OpType.IF:
                print('%s:%d:%d: ERROR: `else` can only be used in `if`-blocks' % program[if_ip]['loc'])
                exit(1)
            program[if_ip].jmp = ip + 1
            stack.append(ip)
        elif op.typ == OpType.END:
            block_ip = stack.pop()
            if program[block_ip].typ == OpType.IF or program[block_ip].typ == OpType.ELSE:
                program[block_ip].jmp = ip
                program[ip].jmp = ip + 1
            elif program[block_ip].typ == OpType.DO:
                assert program[block_ip].jmp is not None
                program[ip].jmp = program[block_ip].jmp
                program[block_ip].jmp = ip + 1
            else:
                print('%s:%d:%d: ERROR: `end` can only close `if`, `else` or `do` blocks for now' % program[block_ip].loc)
                exit(1)
        elif op.typ == OpType.WHILE:
            stack.append(ip)
        elif op.typ == OpType.DO:
            while_ip = stack.pop()
            program[ip].jmp = while_ip
            stack.append(ip)

    if len(stack) > 0:
        print('%s:%d:%d: ERROR: unclosed block' % program[stack.pop()].loc)
        exit(1)

    return program

def find_col(line: int, start: int, predicate: Callable[[str], bool]) -> int:
    while start < len(line) and not predicate(line[start]):
        start += 1
    return start

# TODO: lexer does not support new lines inside of the string literals
def lex_line(line: str) -> Generator[Tuple[int, TokenType, str], None, None]:
    col = find_col(line, 0, lambda x: not x.isspace())
    while col < len(line):
        col_end = None
        if line[col] == '"':
            col_end = find_col(line, col+1, lambda x: x == '"')
            # TODO: report unclosed string literals as proper compiler errors instead of python asserts
            assert line[col_end] == '"'
            text_of_token = line[col+1:col_end]
            # TODO: converted text_of_token to bytes and back just to unescape things is kinda sus ngl
            # Let's try to do something about that, for instance, open the file with "rb" in lex_file()
            yield (col, TokenType.STR, bytes(text_of_token, "utf-8").decode("unicode_escape"))
            col = find_col(line, col_end+1, lambda x: not x.isspace())
        else:
            col_end = find_col(line, col, lambda x: x.isspace())
            text_of_token = line[col:col_end]
            try:
                yield (col, TokenType.INT, int(text_of_token))
            except ValueError:
                yield (col, TokenType.WORD, text_of_token)
            col = find_col(line, col_end, lambda x: not x.isspace())

def lex_file(file_path: str) -> List[Token]:
    with open(file_path, "r") as f:
        return [Token(token_type, (file_path, row + 1, col + 1), token_value)
                for (row, line) in enumerate(f.readlines())
                for (col, token_type, token_value) in lex_line(line.split('//')[0])]

def compile_file_to_program(file_path: str) -> Program:
    return compile_tokens_to_program(lex_file(file_path))

def cmd_call_echoed(cmd: List[str]) -> int:
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.call(cmd)

def usage(compiler_name: str):
    print("Usage: %s [OPTIONS] <SUBCOMMAND> [ARGS]" % compiler_name)
    print("  OPTIONS:")
    print("    -debug                Enable debug mode.")
    print("  SUBCOMMAND:")
    print("    sim <file>            Simulate the program")
    print("    com [OPTIONS] <file>  Compile the program")
    print("      OPTIONS:")
    print("        -r                  Run the program after successful compilation")
    print("        -o <file|dir>       Customize the output path")
    print("    help                  Print this help to stdout and exit with 0 code")

# TODO: there is no way to access command line arguments

if __name__ == '__main__' and '__file__' in globals():
    argv = sys.argv
    assert len(argv) >= 1
    compiler_name, *argv = argv

    while len(argv) > 0:
        if argv[0] == '-debug':
            debug = True
            argv = argv[1:]
        else:
            break

    if debug:
        print("[INFO] Debug mode is enabled")

    if len(argv) < 1:
        usage(compiler_name)
        print("[ERROR] no subcommand is provided")
        exit(1)
    subcommand, *argv = argv

    if subcommand == "sim":
        if len(argv) < 1:
            usage(compiler_name)
            print("[ERROR] no input file is provided for the simulation")
            exit(1)
        program_path, *argv = argv
        program = compile_file_to_program(program_path);
        simulate_little_endian_linux(program)
    elif subcommand == "com":
        run = False
        program_path = None
        output_path = None
        while len(argv) > 0:
            arg, *argv = argv
            if arg == '-r':
                run = True
            elif arg == '-o':
                if len(argv) == 0:
                    usage(compiler_name)
                    print("[ERROR] no argument is provided for parameter -o")
                    exit(1)
                output_path, *argv = argv
            else:
                program_path = arg
                break

        if program_path is None:
            usage(compiler_name)
            print("[ERROR] no input file is provided for the compilation")
            exit(1)

        basename = None
        basedir = None
        if output_path is not None:
            if path.isdir(output_path):
                basename = path.basename(program_path)
                porth_ext = '.porth'
                if basename.endswith(porth_ext):
                    basename = basename[:-len(porth_ext)]
                basedir = path.dirname(output_path)
            else:
                basename = path.basename(output_path)
                basedir = path.dirname(output_path)
        else:
            basename = path.basename(program_path)
            porth_ext = '.porth'
            if basename.endswith(porth_ext):
                basename = basename[:-len(porth_ext)]
            basedir = path.dirname(program_path)
        basepath = path.join(basedir, basename)

        print("[INFO] Generating %s" % (basepath + ".asm"))
        program = compile_file_to_program(program_path);
        generate_nasm_linux_x86_64(program, basepath + ".asm")
        cmd_call_echoed(["nasm", "-felf64", basepath + ".asm"])
        cmd_call_echoed(["ld", "-o", basepath, basepath + ".o"])
        if run:
            exit(cmd_call_echoed([basepath] + argv))
    elif subcommand == "help":
        usage(compiler_name)
        exit(0)
    else:
        usage(compiler_name)
        print("[ERROR] unknown subcommand %s" % (subcommand))
        exit(1)
