#!/usr/bin/env python3

import sys
import subprocess
from os import path

iota_counter=0
def iota(reset=False):
    global iota_counter
    if reset:
        iota_counter = 0
    result = iota_counter
    iota_counter += 1
    return result

OP_PUSH=iota(True)
OP_PLUS=iota()
OP_MINUS=iota()
OP_DUMP=iota()
COUNT_OPS=iota()

def push(x):
    return (OP_PUSH, x)

def plus():
    return (OP_PLUS, )

def minus():
    return (OP_MINUS, )

def dump():
    return (OP_DUMP, )

def simulate_program(program):
    stack = []
    for op in program:
        assert COUNT_OPS == 4, "Exhaustive handling of operations in simulation"
        if op[0] == OP_PUSH:
            stack.append(op[1])
        elif op[0] == OP_PLUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
        elif op[0] == OP_MINUS:
            a = stack.pop()
            b = stack.pop()
            stack.append(b - a)
        elif op[0] == OP_DUMP:
            a = stack.pop()
            print(a)
        else:
            assert False, "unreachable"

def compile_program(program, out_file_path):
    with open(out_file_path, "w") as out:
        out.write("segment .text\n")
        out.write("dump:\n")
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
        for op in program:
            assert COUNT_OPS == 4, "Exhaustive handling of ops in compilation"
            if op[0] == OP_PUSH:
                out.write("    ;; -- push %d --\n" % op[1])
                out.write("    push %d\n" % op[1])
            elif op[0] == OP_PLUS:
                out.write("    ;; -- plus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    add rax, rbx\n")
                out.write("    push rax\n")
            elif op[0] == OP_MINUS:
                out.write("    ;; -- minus --\n")
                out.write("    pop rax\n")
                out.write("    pop rbx\n")
                out.write("    sub rbx, rax\n")
                out.write("    push rbx\n")
            elif op[0] == OP_DUMP:
                out.write("    ;; -- dump --\n")
                out.write("    pop rdi\n")
                out.write("    call dump\n")
            else:
                assert False, "unreachable"

        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")

def parse_word_as_op(word):
    assert COUNT_OPS == 4, "Exhaustive op handling in parse_word_as_op"
    if word == '+':
        return plus()
    elif word == '-':
        return minus()
    elif word == '.':
        return dump()
    else:
        return push(int(word))

def load_program_from_file(file_path):
    with open(file_path, "r") as f:
        return [parse_word_as_op(word) for word in f.read().split()]

def call_cmd(cmd):
    print(cmd)
    subprocess.call(cmd)

def usage(compiler_name):
    print("Usage: %s <SUBCOMMAND> [ARGS]" % compiler_name)
    print("SUBCOMMANDS:")
    print("    sim <file>       Simulate the program")
    print("    com <file>       Compile the program")
    print("    help             Print this help to stdout and exit with 0 code")

if __name__ == '__main__':
    argv = sys.argv
    assert len(argv) >= 1
    compiler_name, *argv = argv
    if len(argv) < 1:
        usage(compiler_name)
        print("ERROR: no subcommand is provided")
        exit(1)
    subcommand, *argv = argv

    if subcommand == "sim":
        if len(argv) < 1:
            usage(compiler_name)
            print("ERROR: no input file is provided for the simulation")
            exit(1)
        program_path, *argv = argv
        program = load_program_from_file(program_path);
        simulate_program(program)
    elif subcommand == "com":
        if len(argv) < 1:
            usage(compiler_name)
            print("ERROR: no input file is provided for the compilation")
            exit(1)
        program_path, *argv = argv
        program = load_program_from_file(program_path);
        porth_ext = '.porth'
        basename = path.basename(program_path)
        if basename.endswith(porth_ext):
            basename = basename[:-len(porth_ext)]
        compile_program(program, basename + ".asm")
        call_cmd(["nasm", "-felf64", basename + ".asm"])
        call_cmd(["ld", "-o", basename, basename + ".o"])
    elif subcommand == "help":
        usage(compiler_name)
        exit(0)
    else:
        usage()
        print("ERROR: unknown subcommand %s" % (subcommand))
        exit(1)
