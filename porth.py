#!/usr/bin/env python3

import os
import sys
import subprocess
import shlex
from os import path
from typing import *
from enum import IntEnum, Enum, auto
from dataclasses import dataclass
from copy import copy
from time import sleep
import traceback

PORTH_EXT = '.porth'
DEFAULT_EXPANSION_LIMIT=1000
EXPANSION_DIAGNOSTIC_LIMIT=10
X86_64_RET_STACK_CAP=8192
SIM_NULL_POINTER_PADDING = 1 # just a little bit of a padding at the beginning of the memory to make 0 an invalid address
SIM_STR_CAPACITY  = 640_000
SIM_ARGV_CAPACITY = 640_000
SIM_LOCAL_MEMORY_CAPACITY = 640_000

debug=False

Loc=Tuple[str, int, int]

class Keyword(Enum):
    IF=auto()
    IFSTAR=auto()
    ELSE=auto()
    END=auto()
    WHILE=auto()
    DO=auto()
    MACRO=auto()
    INCLUDE=auto()
    MEMORY=auto()
    PROC=auto()
    CONST=auto()
    OFFSET=auto()
    RESET=auto()

class DataType(IntEnum):
    INT=auto()
    BOOL=auto()
    PTR=auto()

assert len(DataType) == 3, 'Exhaustive casts for all data types'
class Intrinsic(Enum):
    PLUS=auto()
    MINUS=auto()
    MUL=auto()
    # TODO: split divmod intrinsic into div and mod back
    # It was never useful
    DIVMOD=auto()
    EQ=auto()
    GT=auto()
    LT=auto()
    GE=auto()
    LE=auto()
    NE=auto()
    SHR=auto()
    SHL=auto()
    OR=auto()
    AND=auto()
    NOT=auto()
    PRINT=auto()
    DUP=auto()
    SWAP=auto()
    DROP=auto()
    OVER=auto()
    ROT=auto()
    LOAD8=auto()
    STORE8=auto()
    LOAD16=auto()
    STORE16=auto()
    LOAD32=auto()
    STORE32=auto()
    LOAD64=auto()
    STORE64=auto()
    CAST_PTR=auto()
    CAST_INT=auto()
    CAST_BOOL=auto()
    ARGC=auto()
    ARGV=auto()
    HERE=auto()
    SYSCALL0=auto()
    SYSCALL1=auto()
    SYSCALL2=auto()
    SYSCALL3=auto()
    SYSCALL4=auto()
    SYSCALL5=auto()
    SYSCALL6=auto()

class OpType(Enum):
    PUSH_INT=auto()
    PUSH_STR=auto()
    PUSH_CSTR=auto()
    PUSH_MEM=auto()
    PUSH_LOCAL_MEM=auto()
    INTRINSIC=auto()
    IF=auto()
    IFSTAR=auto()
    ELSE=auto()
    END=auto()
    WHILE=auto()
    DO=auto()
    SKIP_PROC=auto()
    PREP_PROC=auto()
    RET=auto()
    CALL=auto()

class TokenType(Enum):
    WORD=auto()
    INT=auto()
    STR=auto()
    CSTR=auto()
    CHAR=auto()
    KEYWORD=auto()

assert len(TokenType) == 6, "Exhaustive Token type definition. The `value` field of the Token dataclass may require an update"
@dataclass
class Token:
    typ: TokenType
    text: str
    loc: Loc
    value: Union[int, str, Keyword]
    # https://www.python.org/dev/peps/pep-0484/#forward-references
    expanded_from: Optional['Token'] = None
    expanded_count: int = 0

OpAddr=int
MemAddr=int

@dataclass
class Op:
    typ: OpType
    token: Token
    operand: Optional[Union[int, str, Intrinsic, OpAddr]] = None

@dataclass
class Program:
    ops: List[Op]
    memory_capacity: int

def get_cstr_from_mem(mem: bytearray, ptr: int) -> bytes:
    end = ptr
    while mem[end] != 0:
        end += 1
    return mem[ptr:end]

def simulate_little_endian_linux(program: Program, argv: List[str]):
    AT_FDCWD=-100
    O_RDONLY=0
    ENOENT=2
    CLOCK_MONOTONIC=1

    stack: List[int] = []
    # TODO: I think ret_stack should be located in the local memory just like on x86_64
    ret_stack: List[OpAddr] = []
    mem = bytearray(SIM_NULL_POINTER_PADDING + SIM_STR_CAPACITY + SIM_ARGV_CAPACITY + SIM_LOCAL_MEMORY_CAPACITY + program.memory_capacity)

    str_buf_ptr  = SIM_NULL_POINTER_PADDING
    str_ptrs: Dict[int, int] = {}
    str_size = 0

    argv_buf_ptr = SIM_NULL_POINTER_PADDING + SIM_STR_CAPACITY
    argc = 0

    local_memory_ptr = SIM_NULL_POINTER_PADDING + SIM_STR_CAPACITY + SIM_ARGV_CAPACITY
    local_memory_rsp = local_memory_ptr + SIM_LOCAL_MEMORY_CAPACITY

    mem_buf_ptr  = SIM_NULL_POINTER_PADDING + SIM_STR_CAPACITY + SIM_ARGV_CAPACITY + SIM_LOCAL_MEMORY_CAPACITY

    fds: List[BinaryIO] = [sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer]

    for arg in argv:
        value = arg.encode('utf-8')
        n = len(value)

        arg_ptr = str_buf_ptr + str_size
        mem[arg_ptr:arg_ptr+n] = value
        mem[arg_ptr+n] = 0
        str_size += n + 1
        assert str_size <= SIM_STR_CAPACITY, "String buffer overflow"

        argv_ptr = argv_buf_ptr+argc*8
        mem[argv_ptr:argv_ptr+8] = arg_ptr.to_bytes(8, byteorder='little')
        argc += 1
        assert argc*8 <= SIM_ARGV_CAPACITY, "Argv buffer, overflow"

    ip = 0
    while ip < len(program.ops):
        assert len(OpType) == 16, "Exhaustive op handling in simulate_little_endian_linux"
        op = program.ops[ip]
        try:
            if op.typ == OpType.PUSH_INT:
                assert isinstance(op.operand, int), "This could be a bug in the parsing step"
                stack.append(op.operand)
                ip += 1
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
                value = op.operand.encode('utf-8')
                n = len(value)
                stack.append(n)
                if ip not in str_ptrs:
                    str_ptr = str_buf_ptr+str_size
                    str_ptrs[ip] = str_ptr
                    mem[str_ptr:str_ptr+n] = value
                    str_size += n
                    assert str_size <= SIM_STR_CAPACITY, "String buffer overflow"
                stack.append(str_ptrs[ip])
                ip += 1
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
                value = op.operand.encode('utf-8') + b'\0'
                n = len(value)
                if ip not in str_ptrs:
                    str_ptr = str_buf_ptr+str_size
                    str_ptrs[ip] = str_ptr
                    mem[str_ptr:str_ptr+n] = value
                    str_size += n
                    assert str_size <= SIM_STR_CAPACITY, "String buffer overflow"
                stack.append(str_ptrs[ip])
                ip += 1
            elif op.typ == OpType.PUSH_MEM:
                assert isinstance(op.operand, MemAddr), "This could be a bug in the parsing step"
                stack.append(mem_buf_ptr + op.operand)
                ip += 1
            elif op.typ == OpType.PUSH_LOCAL_MEM:
                assert isinstance(op.operand, MemAddr)
                stack.append(local_memory_rsp + op.operand)
                ip += 1
            elif op.typ in [OpType.IF, OpType.IFSTAR]:
                a = stack.pop()
                if a == 0:
                    assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                    ip = op.operand
                else:
                    ip += 1
            elif op.typ == OpType.WHILE:
                ip += 1
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ip = op.operand
            elif op.typ == OpType.END:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ip = op.operand
            elif op.typ == OpType.DO:
                a = stack.pop()
                if a == 0:
                    assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                    ip = op.operand
                else:
                    ip += 1
            elif op.typ == OpType.SKIP_PROC:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ip = op.operand
            elif op.typ == OpType.PREP_PROC:
                assert isinstance(op.operand, int)
                local_memory_rsp -= op.operand
                ip += 1
            elif op.typ == OpType.RET:
                assert isinstance(op.operand, int)
                local_memory_rsp += op.operand
                ip = ret_stack.pop()
            elif op.typ == OpType.CALL:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                ret_stack.append(ip + 1)
                ip = op.operand
            elif op.typ == OpType.INTRINSIC:
                assert len(Intrinsic) == 42, "Exhaustive handling of intrinsic in simulate_little_endian_linux()"
                if op.operand == Intrinsic.PLUS:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(a + b)
                    ip += 1
                elif op.operand == Intrinsic.MINUS:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(b - a)
                    ip += 1
                elif op.operand == Intrinsic.MUL:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(b * a)
                    ip += 1
                elif op.operand == Intrinsic.DIVMOD:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(b // a)
                    stack.append(b % a)
                    ip += 1
                elif op.operand == Intrinsic.EQ:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(a == b))
                    ip += 1
                elif op.operand == Intrinsic.GT:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b > a))
                    ip += 1
                elif op.operand == Intrinsic.LT:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b < a))
                    ip += 1
                elif op.operand == Intrinsic.GE:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b >= a))
                    ip += 1
                elif op.operand == Intrinsic.LE:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b <= a))
                    ip += 1
                elif op.operand == Intrinsic.NE:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b != a))
                    ip += 1
                elif op.operand == Intrinsic.SHR:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b >> a))
                    ip += 1
                elif op.operand == Intrinsic.SHL:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(b << a))
                    ip += 1
                elif op.operand == Intrinsic.OR:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(a | b))
                    ip += 1
                elif op.operand == Intrinsic.AND:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(int(a & b))
                    ip += 1
                elif op.operand == Intrinsic.NOT:
                    a = stack.pop()
                    stack.append(int(~a))
                    ip += 1
                elif op.operand == Intrinsic.PRINT:
                    a = stack.pop()
                    fds[1].write(b"%d\n" % a)
                    fds[1].flush()
                    ip += 1
                elif op.operand == Intrinsic.DUP:
                    a = stack.pop()
                    stack.append(a)
                    stack.append(a)
                    ip += 1
                elif op.operand == Intrinsic.SWAP:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(a)
                    stack.append(b)
                    ip += 1
                elif op.operand == Intrinsic.DROP:
                    stack.pop()
                    ip += 1
                elif op.operand == Intrinsic.OVER:
                    a = stack.pop()
                    b = stack.pop()
                    stack.append(b)
                    stack.append(a)
                    stack.append(b)
                    ip += 1
                elif op.operand == Intrinsic.ROT:
                    a = stack.pop()
                    b = stack.pop()
                    c = stack.pop()
                    stack.append(b)
                    stack.append(a)
                    stack.append(c)
                    ip += 1
                elif op.operand == Intrinsic.LOAD8:
                    addr = stack.pop()
                    byte = mem[addr]
                    stack.append(byte)
                    ip += 1
                elif op.operand == Intrinsic.STORE8:
                    store_addr = stack.pop()
                    store_value = stack.pop()
                    mem[store_addr] = store_value & 0xFF
                    ip += 1
                elif op.operand == Intrinsic.LOAD16:
                    load_addr = stack.pop()
                    stack.append(int.from_bytes(mem[load_addr:load_addr+2], byteorder="little"))
                    ip += 1
                elif op.operand == Intrinsic.STORE16:
                    store_addr = stack.pop();
                    store_value = stack.pop()
                    mem[store_addr:store_addr+2] = store_value.to_bytes(length=2, byteorder="little", signed=(store_value < 0));
                    ip += 1
                elif op.operand == Intrinsic.LOAD32:
                    load_addr = stack.pop()
                    stack.append(int.from_bytes(mem[load_addr:load_addr+4], byteorder="little"))
                    ip += 1
                elif op.operand == Intrinsic.STORE32:
                    store_addr = stack.pop();
                    store_value = stack.pop()
                    mem[store_addr:store_addr+4] = store_value.to_bytes(length=4, byteorder="little", signed=(store_value < 0));
                    ip += 1
                elif op.operand == Intrinsic.LOAD64:
                    load_addr = stack.pop()
                    stack.append(int.from_bytes(mem[load_addr:load_addr+8], byteorder="little"))
                    ip += 1
                elif op.operand == Intrinsic.STORE64:
                    store_addr = stack.pop();
                    store_value = stack.pop()
                    mem[store_addr:store_addr+8] = store_value.to_bytes(length=8, byteorder="little", signed=(store_value < 0));
                    ip += 1
                elif op.operand == Intrinsic.ARGC:
                    stack.append(argc)
                    ip += 1
                elif op.operand == Intrinsic.ARGV:
                    stack.append(argv_buf_ptr)
                    ip += 1
                elif op.operand == Intrinsic.HERE:
                    value = ("%s:%d:%d" % op.token.loc).encode('utf-8')
                    n = len(value)
                    stack.append(n)
                    if ip not in str_ptrs:
                        str_ptr = str_buf_ptr+str_size
                        str_ptrs[ip] = str_ptr
                        mem[str_ptr:str_ptr+n] = value
                        str_size += n
                        assert str_size <= SIM_STR_CAPACITY, "String buffer overflow"
                    stack.append(str_ptrs[ip])
                    ip += 1
                elif op.operand == Intrinsic.CAST_PTR:
                    # Ignore the type casting. It's only useful for type_check_program() phase
                    ip += 1
                elif op.operand == Intrinsic.CAST_BOOL:
                    # Ignore the type casting. It's only useful for type_check_program() phase
                    ip += 1
                elif op.operand == Intrinsic.CAST_INT:
                    # Ignore the type casting. It's only useful for type_check_program() phase
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL0:
                    syscall_number = stack.pop();
                    if syscall_number == 39: # SYS_getpid
                        stack.append(os.getpid());
                    else:
                        assert False, "unknown syscall number %d" % syscall_number
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL1:
                    syscall_number = stack.pop()
                    arg1 = stack.pop()
                    if syscall_number == 60: # SYS_exit
                        exit(arg1)
                    elif syscall_number == 3: # SYS_close
                        fds[arg1].close()
                        stack.append(0)
                    else:
                        assert False, "unknown syscall number %d" % syscall_number
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL2:
                    assert False, "not implemented"
                elif op.operand == Intrinsic.SYSCALL3:
                    syscall_number = stack.pop()
                    arg1 = stack.pop()
                    arg2 = stack.pop()
                    arg3 = stack.pop()
                    if syscall_number == 0: # SYS_read
                        fd = arg1
                        buf = arg2
                        count = arg3
                        # NOTE: trying to behave like a POSIX tty in canonical mode by making the data available
                        # on each newline
                        # https://en.wikipedia.org/wiki/POSIX_terminal_interface#Canonical_mode_processing
                        data = fds[fd].readline(count)
                        mem[buf:buf+len(data)] = data
                        stack.append(len(data))
                    elif syscall_number == 1: # SYS_write
                        fd = arg1
                        buf = arg2
                        count = arg3
                        fds[fd].write(mem[buf:buf+count])
                        fds[fd].flush()
                        stack.append(count)
                    else:
                        assert False, "unknown syscall number %d" % syscall_number
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL4:
                    syscall_number = stack.pop()
                    arg1 = stack.pop()
                    arg2 = stack.pop()
                    arg3 = stack.pop()
                    arg4 = stack.pop()

                    if syscall_number == 230: # clock_nanosleep
                        clock_id = arg1
                        flags = arg2
                        request_ptr = arg3
                        remain_ptr = arg4
                        assert clock_id == CLOCK_MONOTONIC, "Only CLOCK_MONOTONIC is implemented for SYS_clock_nanosleep"
                        assert flags == 0, "Only relative time is supported for SYS_clock_nanosleep"
                        assert request_ptr != 0, "request cannot be NULL for SYS_clock_nanosleep. We should probably return -1 in that case..."
                        assert remain_ptr == 0, "remain is not supported for SYS_clock_nanosleep"
                        seconds = int.from_bytes(mem[request_ptr:request_ptr+8], byteorder='little')
                        nano_seconds = int.from_bytes(mem[request_ptr+8:request_ptr+8+8], byteorder='little')
                        sleep(float(seconds)+float(nano_seconds)*1e-09)
                        stack.append(0)
                    elif syscall_number == 257: # SYS_openat
                        dirfd = arg1
                        pathname_ptr = arg2
                        flags = arg3
                        mode = arg4
                        if dirfd != AT_FDCWD:
                            assert False, f"openat: unsupported dirfd: {dirfd}"
                        if flags != O_RDONLY:
                            assert False, f"openat: unsupported flags: {flags}"
                        if mode != 0:
                            assert False, f"openat: unsupported mode: {mode}"
                        pathname = get_cstr_from_mem(mem, pathname_ptr).decode('utf-8')
                        fd = len(fds)
                        try:
                            fds.append(open(pathname, 'rb'))
                            stack.append(fd)
                        except FileNotFoundError:
                            stack.append(-ENOENT)
                    else:
                        assert False, "unknown syscall number %d" % syscall_number
                    ip += 1
                elif op.operand == Intrinsic.SYSCALL5:
                    assert False, "not implemented"
                elif op.operand == Intrinsic.SYSCALL6:
                    assert False, "not implemented"
                else:
                    assert False, "unreachable"
            else:
                assert False, "unreachable"
        except Exception as e:
            compiler_error_with_expansion_stack(op.token, "Python Exception during simulation")
            traceback.print_exception(type(e), e, e.__traceback__)
            exit(1)

def compiler_diagnostic(loc: Loc, tag: str, message: str):
    print("%s:%d:%d: %s: %s" % (loc + (tag, message)), file=sys.stderr)

def compiler_diagnostic_with_expansion_stack(token: Token, tag: str, message: str):
    compiler_diagnostic(token.loc, tag, message)
    stack = token.expanded_from
    limit = 0
    while stack is not None and limit <= EXPANSION_DIAGNOSTIC_LIMIT:
        compiler_note(stack.loc, "expanded from `%s`" % stack.text)
        stack = stack.expanded_from
        limit += 1
    if limit > EXPANSION_DIAGNOSTIC_LIMIT:
        print('...', file=sys.stderr)
        print('... too many expansions ...', file=sys.stderr)
        print('...', file=sys.stderr)

def compiler_error(loc: Loc, message: str):
    compiler_diagnostic(loc, 'ERROR', message)

def compiler_error_with_expansion_stack(token: Token, message: str):
    compiler_diagnostic_with_expansion_stack(token, 'ERROR', message)

def compiler_note(loc: Loc, message: str):
    compiler_diagnostic(loc, 'NOTE', message)

def not_enough_arguments(op: Op):
    assert len(OpType) == 16, f"Exhaustive handling of Op types in not_enough_arguments() (expected {len(OpType)}). Keep in mind that not all of the ops should be handled in here. Only those that consume elements from the stack."
    if op.typ == OpType.INTRINSIC:
        assert isinstance(op.operand, Intrinsic)
        compiler_error_with_expansion_stack(op.token, "not enough arguments for the `%s` intrinsic" % INTRINSIC_NAMES[op.operand])
    elif op.typ == OpType.DO:
        compiler_error_with_expansion_stack(op.token, "not enough arguments for the do-block")
    else:
        assert False, "unsupported type of operation"

DataStack=List[Tuple[DataType, Token]]

@dataclass
class Context:
    stack: DataStack
    ret_stack: List[OpAddr]
    ip: OpAddr

CallPath=Tuple[OpAddr, ...]

# TODO: better error reporting on type checking errors of intrinsics
# Reported expected and actual types with the location that introduced the actual type
# TODO: better error reporting on type checking errors of procs
# Show the call path and stuff (like for macros)
def type_check_program(program: Program):
    visited_dos: Dict[CallPath, DataStack] = {}
    contexts: List[Context] = [Context(stack=[], ip=0, ret_stack=[])]
    while len(contexts) > 0:
        ctx = contexts[-1];
        if ctx.ip >= len(program.ops):
            if len(ctx.stack) != 0:
                compiler_error_with_expansion_stack(ctx.stack[-1][1], "unhandled data on the data stack: %s" % list(map(lambda x: x[0], ctx.stack)))
                exit(1)
            contexts.pop()
            continue
        op = program.ops[ctx.ip]
        assert len(OpType) == 16, "Exhaustive ops handling in type_check_program()"
        if op.typ == OpType.PUSH_INT:
            ctx.stack.append((DataType.INT, op.token))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_STR:
            ctx.stack.append((DataType.INT, op.token))
            ctx.stack.append((DataType.PTR, op.token))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_CSTR:
            ctx.stack.append((DataType.PTR, op.token))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_MEM:
            ctx.stack.append((DataType.PTR, op.token))
            ctx.ip += 1
        elif op.typ == OpType.PUSH_LOCAL_MEM:
            ctx.stack.append((DataType.PTR, op.token))
            ctx.ip += 1
        elif op.typ == OpType.SKIP_PROC:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.PREP_PROC:
            ctx.ip += 1
        elif op.typ == OpType.CALL:
            ctx.ret_stack.append(ctx.ip + 1)
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.RET:
            ctx.ip = ctx.ret_stack.pop()
        elif op.typ == OpType.INTRINSIC:
            assert len(Intrinsic) == 42, "Exhaustive intrinsic handling in type_check_program()"
            assert isinstance(op.operand, Intrinsic), "This could be a bug in compilation step"
            if op.operand == Intrinsic.PLUS:
                assert len(DataType) == 3, "Exhaustive type handling in PLUS intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == DataType.INT and b_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                elif a_type == DataType.INT and b_type == DataType.PTR:
                    ctx.stack.append((DataType.PTR, op.token))
                elif a_type == DataType.PTR and b_type == DataType.INT:
                    ctx.stack.append((DataType.PTR, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument types for PLUS intrinsic. Expected INT or PTR")
                    exit(1)
            elif op.operand == Intrinsic.MINUS:
                assert len(DataType) == 3, "Exhaustive type handling in MINUS intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and (a_type == DataType.INT or a_type == DataType.PTR):
                    ctx.stack.append((DataType.INT, op.token))
                elif b_type == DataType.PTR and a_type == DataType.INT:
                    ctx.stack.append((DataType.PTR, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument types fo MINUS intrinsic: %s" % [b_type, a_type])
                    exit(1)
            elif op.operand == Intrinsic.MUL:
                assert len(DataType) == 3, "Exhaustive type handling in MUL intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument types fo MUL intrinsic. Expected INT.")
                    exit(1)
            elif op.operand == Intrinsic.DIVMOD:
                assert len(DataType) == 3, "Exhaustive type handling in DIVMOD intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument types fo DIVMOD intrinsic. Expected INT.")
                    exit(1)
            elif op.operand == Intrinsic.EQ:
                assert len(DataType) == 3, "Exhaustive type handling in EQ intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument types fo EQ intrinsic.")
                    exit(1)
            elif op.operand == Intrinsic.GT:
                assert len(DataType) == 3, "Exhaustive type handling in GT intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for GT intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LT:
                assert len(DataType) == 3, "Exhaustive type handling in LT intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for LT intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.GE:
                assert len(DataType) == 3, "Exhaustive type handling in GE intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for GE intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LE:
                assert len(DataType) == 3, "Exhaustive type handling in LE intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for LE intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.NE:
                assert len(DataType) == 3, "Exhaustive type handling in NE intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for NE intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.SHR:
                assert len(DataType) == 3, "Exhaustive type handling in SHR intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for SHR intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.SHL:
                assert len(DataType) == 3, "Exhaustive type handling in SHL intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for SHL intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.OR:
                assert len(DataType) == 3, "Exhaustive type handling in OR intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                elif a_type == b_type and a_type == DataType.BOOL:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for OR intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.AND:
                assert len(DataType) == 3, "Exhaustive type handling in AND intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == b_type and a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                elif a_type == b_type and a_type == DataType.BOOL:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for AND intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.NOT:
                assert len(DataType) == 3, "Exhaustive type handling in NOT intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.INT:
                    ctx.stack.append((DataType.INT, op.token))
                elif a_type == DataType.BOOL:
                    ctx.stack.append((DataType.BOOL, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for NOT intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.PRINT:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                ctx.stack.pop()
            elif op.operand == Intrinsic.DUP:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a = ctx.stack.pop()
                ctx.stack.append(a)
                ctx.stack.append(a)
            elif op.operand == Intrinsic.SWAP:
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a = ctx.stack.pop()
                b = ctx.stack.pop()
                ctx.stack.append(a)
                ctx.stack.append(b)
            elif op.operand == Intrinsic.DROP:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                ctx.stack.pop()
            elif op.operand == Intrinsic.OVER:
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                a = ctx.stack.pop()
                b = ctx.stack.pop()
                ctx.stack.append(b)
                ctx.stack.append(a)
                ctx.stack.append(b)
            elif op.operand == Intrinsic.ROT:
                if len(ctx.stack) < 3:
                    not_enough_arguments(op)
                    exit(1)
                a = ctx.stack.pop()
                b = ctx.stack.pop()
                c = ctx.stack.pop()
                ctx.stack.append(b)
                ctx.stack.append(a)
                ctx.stack.append(c)
            elif op.operand == Intrinsic.LOAD8:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD8 intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.PTR:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for LOAD8 intrinsic: %s" % a_type)
                    exit(1)
            elif op.operand == Intrinsic.STORE8:
                assert len(DataType) == 3, "Exhaustive type handling in STORE8 intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == DataType.PTR and b_type == DataType.INT:
                    pass
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for STORE8 intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LOAD16:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD16 intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.PTR:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for LOAD16 intrinsic: %s" % a_type)
                    exit(1)
            elif op.operand == Intrinsic.STORE16:
                assert len(DataType) == 3, "Exhaustive type handling in STORE16 intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == DataType.PTR and b_type == DataType.INT:
                    pass
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for STORE16 intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LOAD32:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD32 intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.PTR:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for LOAD32 intrinsic: %s" % a_type)
                    exit(1)
            elif op.operand == Intrinsic.STORE32:
                assert len(DataType) == 3, "Exhaustive type handling in STORE32 intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if a_type == DataType.PTR and b_type == DataType.INT:
                    pass
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for STORE32 intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.LOAD64:
                assert len(DataType) == 3, "Exhaustive type handling in LOAD64 intrinsic"
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                a_type, a_loc = ctx.stack.pop()

                if a_type == DataType.PTR:
                    ctx.stack.append((DataType.INT, op.token))
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for LOAD64 intrinsic")
                    exit(1)
            elif op.operand == Intrinsic.STORE64:
                assert len(DataType) == 3, "Exhaustive type handling in STORE64 intrinsic"
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_loc = ctx.stack.pop()
                b_type, b_loc = ctx.stack.pop()

                if (b_type == DataType.INT or b_type == DataType.PTR) and a_type == DataType.PTR:
                    pass
                else:
                    compiler_error_with_expansion_stack(op.token, "invalid argument type for STORE64 intrinsic: %s" % [b_type, a_type])
                    exit(1)
            elif op.operand == Intrinsic.CAST_PTR:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_token = ctx.stack.pop()

                ctx.stack.append((DataType.PTR, a_token))
            elif op.operand == Intrinsic.CAST_INT:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_token = ctx.stack.pop()

                ctx.stack.append((DataType.INT, a_token))
            elif op.operand == Intrinsic.CAST_BOOL:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)

                a_type, a_token = ctx.stack.pop()

                ctx.stack.append((DataType.BOOL, a_token))
            elif op.operand == Intrinsic.ARGC:
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.ARGV:
                ctx.stack.append((DataType.PTR, op.token))
            elif op.operand == Intrinsic.HERE:
                ctx.stack.append((DataType.INT, op.token))
                ctx.stack.append((DataType.PTR, op.token))
            # TODO: figure out how to type check syscall arguments and return types
            elif op.operand == Intrinsic.SYSCALL0:
                if len(ctx.stack) < 1:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(1):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL1:
                if len(ctx.stack) < 2:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(2):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL2:
                if len(ctx.stack) < 3:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(3):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL3:
                if len(ctx.stack) < 4:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(4):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL4:
                if len(ctx.stack) < 5:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(5):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL5:
                if len(ctx.stack) < 6:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(6):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            elif op.operand == Intrinsic.SYSCALL6:
                if len(ctx.stack) < 7:
                    not_enough_arguments(op)
                    exit(1)
                for i in range(7):
                    ctx.stack.pop()
                ctx.stack.append((DataType.INT, op.token))
            else:
                assert False, "unreachable"
            ctx.ip += 1
        elif op.typ == OpType.IF:
            if len(ctx.stack) < 1:
                not_enough_arguments(op)
                exit(1)
            a_type, a_token = ctx.stack.pop()
            if a_type != DataType.BOOL:
                compiler_error_with_expansion_stack(op.token, "Invalid argument for the if condition. Expected BOOL.")
                exit(1)
            ctx.ip += 1
            assert isinstance(op.operand, OpAddr)
            contexts.append(Context(stack=copy(ctx.stack), ip=op.operand, ret_stack=copy(ctx.ret_stack)))
            ctx = contexts[-1]
        elif op.typ == OpType.IFSTAR:
            if len(ctx.stack) < 1:
                not_enough_arguments(op)
                exit(1)
            a_type, a_token = ctx.stack.pop()
            if a_type != DataType.BOOL:
                compiler_error_with_expansion_stack(op.token, "Invalid argument for the `if*` condition. Expected BOOL.")
                exit(1)
            ctx.ip += 1
            assert isinstance(op.operand, OpAddr)
            contexts.append(Context(stack=copy(ctx.stack), ip=op.operand, ret_stack=copy(ctx.ret_stack)))
            ctx = contexts[-1]
        elif op.typ == OpType.WHILE:
            ctx.ip += 1
        elif op.typ == OpType.END:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.ELSE:
            assert isinstance(op.operand, OpAddr)
            ctx.ip = op.operand
        elif op.typ == OpType.DO:
            assert isinstance(op.operand, OpAddr)
            if len(ctx.stack) < 1:
                not_enough_arguments(op)
                exit(1)
            a_type, a_token = ctx.stack.pop()
            if a_type != DataType.BOOL:
                compiler_error_with_expansion_stack(op.token, "Invalid argument for the while-do condition. Expected BOOL.")
                exit(1)
            call_path = tuple(ctx.ret_stack + [ctx.ip])
            if call_path in visited_dos:
                expected_types = list(map(lambda x: x[0], visited_dos[call_path]))
                actual_types = list(map(lambda x: x[0], ctx.stack))
                if expected_types != actual_types:
                    compiler_error_with_expansion_stack(op.token, 'Loops are not allowed to alter types and amount of elements on the stack.')
                    compiler_note(op.token.loc, 'Expected elements: %s' % expected_types)
                    compiler_note(op.token.loc, 'Actual elements: %s' % actual_types)
                    exit(1)
                contexts.pop()
            else:
                visited_dos[call_path] = copy(ctx.stack)
                ctx.ip += 1
                contexts.append(Context(stack=copy(ctx.stack), ip=op.operand, ret_stack=copy(ctx.ret_stack)))
                ctx = contexts[-1]
        else:
            assert False, "unreachable"

def generate_nasm_linux_x86_64(program: Program, out_file_path: str):
    strs: List[bytes] = []
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
        out.write("    mov [args_ptr], rsp\n")
        out.write("    mov rax, ret_stack_end\n")
        out.write("    mov [ret_stack_rsp], rax\n")
        for ip in range(len(program.ops)):
            op = program.ops[ip]
            assert len(OpType) == 16, "Exhaustive ops handling in generate_nasm_linux_x86_64"
            out.write("addr_%d:\n" % ip)
            out.write("    ;; -- %s:%d:%d: %s (%s) --\n" % (op.token.loc + (repr(op.token.text), op.typ)))
            if op.typ == OpType.PUSH_INT:
                assert isinstance(op.operand, int), f"This could be a bug in the parsing step {op.operand}"
                out.write("    mov rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
                value = op.operand.encode('utf-8')
                n = len(value)
                out.write("    mov rax, %d\n" % n)
                out.write("    push rax\n")
                out.write("    push str_%d\n" % len(strs))
                strs.append(value)
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str), "This could be a bug in the parsing step"
                value = op.operand.encode('utf-8') + b'\0'
                out.write("    push str_%d\n" % len(strs))
                strs.append(value)
            elif op.typ == OpType.PUSH_MEM:
                assert isinstance(op.operand, MemAddr), "This could be a bug in the parsing step"
                out.write("    mov rax, mem\n")
                out.write("    add rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ == OpType.PUSH_LOCAL_MEM:
                assert isinstance(op.operand, MemAddr)
                out.write("    mov rax, [ret_stack_rsp]\n");
                out.write("    add rax, %d\n" % op.operand)
                out.write("    push rax\n")
            elif op.typ in [OpType.IF, OpType.IFSTAR]:
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert isinstance(op.operand, OpAddr), f"This could be a bug in the parsing step {op.operand}"
                out.write("    jz addr_%d\n" % op.operand)
            elif op.typ == OpType.WHILE:
                pass
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr), "This could be a bug in the parsing step"
                out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.END:
                assert isinstance(op.operand, int), "This could be a bug in the parsing step"
                if ip + 1 != op.operand:
                    out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.DO:
                out.write("    pop rax\n")
                out.write("    test rax, rax\n")
                assert isinstance(op.operand, int), "This could be a bug in the parsing step"
                out.write("    jz addr_%d\n" % op.operand)
            elif op.typ == OpType.SKIP_PROC:
                assert isinstance(op.operand, OpAddr), f"This could be a bug in the parsing step: {op.operand}"
                out.write("    jmp addr_%d\n" % op.operand)
            elif op.typ == OpType.PREP_PROC:
                assert isinstance(op.operand, int)
                out.write("    sub rsp, %d\n" % op.operand)
                out.write("    mov [ret_stack_rsp], rsp\n")
                out.write("    mov rsp, rax\n")
            elif op.typ == OpType.CALL:
                assert isinstance(op.operand, OpAddr), f"This could be a bug in the parsing step: {op.operand}"
                out.write("    mov rax, rsp\n")
                out.write("    mov rsp, [ret_stack_rsp]\n")
                out.write("    call addr_%d\n" % op.operand)
                out.write("    mov [ret_stack_rsp], rsp\n")
                out.write("    mov rsp, rax\n")
            elif op.typ == OpType.RET:
                assert isinstance(op.operand, int)
                out.write("    mov rax, rsp\n")
                out.write("    mov rsp, [ret_stack_rsp]\n")
                out.write("    add rsp, %d\n" % op.operand)
                out.write("    ret\n")
            elif op.typ == OpType.INTRINSIC:
                assert len(Intrinsic) == 42, "Exhaustive intrinsic handling in generate_nasm_linux_x86_64()"
                if op.operand == Intrinsic.PLUS:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    add rax, rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.MINUS:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    sub rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.MUL:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    mul rbx\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.DIVMOD:
                    out.write("    xor rdx, rdx\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rax\n")
                    out.write("    div rbx\n")
                    out.write("    push rax\n");
                    out.write("    push rdx\n");
                elif op.operand == Intrinsic.SHR:
                    out.write("    pop rcx\n")
                    out.write("    pop rbx\n")
                    out.write("    shr rbx, cl\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.SHL:
                    out.write("    pop rcx\n")
                    out.write("    pop rbx\n")
                    out.write("    shl rbx, cl\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.OR:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    or rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.AND:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    and rbx, rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.NOT:
                    out.write("    pop rax\n")
                    out.write("    not rax\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.PRINT:
                    out.write("    pop rdi\n")
                    out.write("    call print\n")
                elif op.operand == Intrinsic.EQ:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmove rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.GT:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovg rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LT:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovl rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.GE:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovge rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LE:
                    out.write("    mov rcx, 0\n");
                    out.write("    mov rdx, 1\n");
                    out.write("    pop rbx\n");
                    out.write("    pop rax\n");
                    out.write("    cmp rax, rbx\n");
                    out.write("    cmovle rcx, rdx\n");
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.NE:
                    out.write("    mov rcx, 0\n")
                    out.write("    mov rdx, 1\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rax\n")
                    out.write("    cmp rax, rbx\n")
                    out.write("    cmovne rcx, rdx\n")
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.DUP:
                    out.write("    pop rax\n")
                    out.write("    push rax\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SWAP:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.DROP:
                    out.write("    pop rax\n")
                elif op.operand == Intrinsic.OVER:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    push rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.ROT:
                    out.write("    pop rax\n")
                    out.write("    pop rbx\n")
                    out.write("    pop rcx\n")
                    out.write("    push rbx\n")
                    out.write("    push rax\n")
                    out.write("    push rcx\n")
                elif op.operand == Intrinsic.LOAD8:
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bl, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE8:
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], bl\n");
                elif op.operand == Intrinsic.LOAD16:
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov bx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE16:
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], bx\n");
                elif op.operand == Intrinsic.LOAD32:
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov ebx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE32:
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], ebx\n");
                elif op.operand == Intrinsic.LOAD64:
                    out.write("    pop rax\n")
                    out.write("    xor rbx, rbx\n")
                    out.write("    mov rbx, [rax]\n")
                    out.write("    push rbx\n")
                elif op.operand == Intrinsic.STORE64:
                    out.write("    pop rax\n");
                    out.write("    pop rbx\n");
                    out.write("    mov [rax], rbx\n");
                elif op.operand == Intrinsic.ARGC:
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    mov rax, [rax]\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.ARGV:
                    out.write("    mov rax, [args_ptr]\n")
                    out.write("    add rax, 8\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.HERE:
                    value = ("%s:%d:%d" % op.token.loc).encode('utf-8')
                    n = len(value)
                    out.write("    mov rax, %d\n" % n)
                    out.write("    push rax\n")
                    out.write("    push str_%d\n" % len(strs))
                    strs.append(value)
                elif op.operand in [Intrinsic.CAST_PTR, Intrinsic.CAST_INT, Intrinsic.CAST_BOOL]:
                    pass
                elif op.operand == Intrinsic.SYSCALL0:
                    out.write("    pop rax\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL1:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL2:
                    out.write("    pop rax\n");
                    out.write("    pop rdi\n");
                    out.write("    pop rsi\n");
                    out.write("    syscall\n");
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL3:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL4:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL5:
                    out.write("    pop rax\n")
                    out.write("    pop rdi\n")
                    out.write("    pop rsi\n")
                    out.write("    pop rdx\n")
                    out.write("    pop r10\n")
                    out.write("    pop r8\n")
                    out.write("    syscall\n")
                    out.write("    push rax\n")
                elif op.operand == Intrinsic.SYSCALL6:
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
            else:
                assert False, "unreachable"

        out.write("addr_%d:\n" % len(program.ops))
        out.write("    mov rax, 60\n")
        out.write("    mov rdi, 0\n")
        out.write("    syscall\n")
        out.write("segment .data\n")
        for index, s in enumerate(strs):
            out.write("str_%d: db %s\n" % (index, ','.join(map(hex, list(s)))))
        out.write("segment .bss\n")
        out.write("args_ptr: resq 1\n")
        out.write("ret_stack_rsp: resq 1\n")
        out.write("ret_stack: resb %d\n" % X86_64_RET_STACK_CAP)
        out.write("ret_stack_end:\n")
        out.write("mem: resb %d\n" % program.memory_capacity)

assert len(Keyword) == 13, "Exhaustive KEYWORD_NAMES definition."
KEYWORD_BY_NAMES: Dict[str, Keyword] = {
    'if': Keyword.IF,
    'if*': Keyword.IFSTAR,
    'else': Keyword.ELSE,
    'while': Keyword.WHILE,
    'do': Keyword.DO,
    'macro': Keyword.MACRO,
    'include': Keyword.INCLUDE,
    'memory': Keyword.MEMORY,
    'proc': Keyword.PROC,
    'end': Keyword.END,
    'const': Keyword.CONST,
    'offset': Keyword.OFFSET,
    'reset': Keyword.RESET,
}
KEYWORD_NAMES: Dict[Keyword, str] = {v: k for k, v in KEYWORD_BY_NAMES.items()}

assert len(Intrinsic) == 42, "Exhaustive INTRINSIC_BY_NAMES definition"
INTRINSIC_BY_NAMES: Dict[str, Intrinsic] = {
    '+': Intrinsic.PLUS,
    '-': Intrinsic.MINUS,
    '*': Intrinsic.MUL,
    'divmod': Intrinsic.DIVMOD,
    'print': Intrinsic.PRINT,
    '=': Intrinsic.EQ,
    '>': Intrinsic.GT,
    '<': Intrinsic.LT,
    '>=': Intrinsic.GE,
    '<=': Intrinsic.LE,
    '!=': Intrinsic.NE,
    'shr': Intrinsic.SHR,
    'shl': Intrinsic.SHL,
    'or': Intrinsic.OR,
    'and': Intrinsic.AND,
    'not': Intrinsic.NOT,
    'dup': Intrinsic.DUP,
    'swap': Intrinsic.SWAP,
    'drop': Intrinsic.DROP,
    'over': Intrinsic.OVER,
    'rot': Intrinsic.ROT,
    '!8': Intrinsic.STORE8,
    '@8': Intrinsic.LOAD8,
    '!16': Intrinsic.STORE16,
    '@16': Intrinsic.LOAD16,
    '!32': Intrinsic.STORE32,
    '@32': Intrinsic.LOAD32,
    '!64': Intrinsic.STORE64,
    '@64': Intrinsic.LOAD64,
    'cast(ptr)': Intrinsic.CAST_PTR,
    'cast(int)': Intrinsic.CAST_INT,
    'cast(bool)': Intrinsic.CAST_BOOL,
    'argc': Intrinsic.ARGC,
    'argv': Intrinsic.ARGV,
    'here': Intrinsic.HERE,
    'syscall0': Intrinsic.SYSCALL0,
    'syscall1': Intrinsic.SYSCALL1,
    'syscall2': Intrinsic.SYSCALL2,
    'syscall3': Intrinsic.SYSCALL3,
    'syscall4': Intrinsic.SYSCALL4,
    'syscall5': Intrinsic.SYSCALL5,
    'syscall6': Intrinsic.SYSCALL6,
}
INTRINSIC_NAMES: Dict[Intrinsic, str] = {v: k for k, v in INTRINSIC_BY_NAMES.items()}

@dataclass
class Macro:
    loc: Loc
    tokens: List[Token]

class HumanNumber(Enum):
    Singular=auto()
    Plural=auto()

def human(obj: TokenType, number: HumanNumber = HumanNumber.Singular) -> str:
    '''Human readable representation of an object that can be used in error messages'''
    assert len(HumanNumber) == 2, "Exhaustive handling of number category in human()"
    if number == HumanNumber.Singular:
        assert len(TokenType) == 6, "Exhaustive handling of token types in human()"
        if obj == TokenType.WORD:
            return "a word"
        elif obj == TokenType.INT:
            return "an integer"
        elif obj == TokenType.STR:
            return "a string"
        elif obj == TokenType.CSTR:
            return "a C-style string"
        elif obj == TokenType.CHAR:
            return "a character"
        elif obj == TokenType.KEYWORD:
            return "a keyword"
        else:
            assert False, "unreachable"
    elif number == HumanNumber.Plural:
        assert len(TokenType) == 6, "Exhaustive handling of token types in human()"
        if obj == TokenType.WORD:
            return "words"
        elif obj == TokenType.INT:
            return "integers"
        elif obj == TokenType.STR:
            return "strings"
        elif obj == TokenType.CSTR:
            return "C-style strings"
        elif obj == TokenType.CHAR:
            return "characters"
        elif obj == TokenType.KEYWORD:
            return "keywords"
        else:
            assert False, "unreachable"
    else:
        assert False, "unreachable"

def expand_macro(macro: Macro, expanded_from: Token) -> List[Token]:
    result = list(map(lambda x: copy(x), macro.tokens))
    for token in result:
        token.expanded_from = expanded_from
        token.expanded_count = expanded_from.expanded_count + 1
    return result

@dataclass
class Memory:
    offset: MemAddr
    loc: Loc

@dataclass
class Proc:
    addr: OpAddr
    loc: Loc
    local_memories: Dict[str, Memory]
    local_memory_capacity: int

@dataclass
class Const:
    value: int
    loc: Loc

def check_word_redefinition(token: Token, memories: Dict[str, Memory], macros: Dict[str, Macro], procs: Dict[str, Proc], consts: Dict[str, Const]):
    assert token.typ == TokenType.WORD
    assert isinstance(token.value, str)
    name: str = token.value
    if name in memories:
        compiler_error_with_expansion_stack(token, "redefinition of a memory region `%s`" % name)
        compiler_note(memories[name].loc, "the original definition is located here")
        exit(1)
    if name in INTRINSIC_BY_NAMES:
        compiler_error_with_expansion_stack(token, "redefinition of an intrinsic word `%s`" % (name, ))
        exit(1)
    if name in macros:
        compiler_error_with_expansion_stack(token, "redefinition of a macro `%s`" % (name, ))
        compiler_note(macros[name].loc, "the original definition is located here")
        exit(1)
    if name in procs:
        compiler_error_with_expansion_stack(token, "redefinition of a proc `%s`" % (name, ))
        compiler_note(procs[name].loc, "the original definition is located here")
        exit(1)
    if name in consts:
        compiler_error_with_expansion_stack(token, "redefinition of a constant `%s`" % (name, ))
        compiler_note(consts[name].loc, "the original definition is located here")
        exit(1)

def eval_const_value(rtokens: List[Token], macros: Dict[str, Macro], consts: Dict[str, Const], iota: List[int]) -> int:
    stack: List[int] = []
    while len(rtokens) > 0:
        token = rtokens.pop()
        if token.typ == TokenType.KEYWORD:
            assert isinstance(token.value, Keyword)
            if token.value == Keyword.END:
                break
            elif token.value == Keyword.OFFSET:
                if len(stack) < 1:
                    compiler_error_with_expansion_stack(token, f"not enough arguments for `{KEYWORD_NAMES[token.value]}` keyword")
                    exit(1)
                offset = stack.pop()
                stack.append(iota[0])
                iota[0] += offset
            elif token.value == Keyword.RESET:
                stack.append(iota[0])
                iota[0] = 0
            else:
                compiler_error_with_expansion_stack(token, f"unsupported keyword `{KEYWORD_NAMES[token.value]}` in compile time evaluation")
                exit(1)
        elif token.typ == TokenType.INT:
            assert isinstance(token.value, int)
            stack.append(token.value)
        elif token.typ == TokenType.WORD:
            assert isinstance(token.value, str)
            if token.value == INTRINSIC_NAMES[Intrinsic.PLUS]:
                if len(stack) < 2:
                    compiler_error_with_expansion_stack(token, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                a = stack.pop()
                b = stack.pop()
                stack.append(a + b)
            elif token.value == INTRINSIC_NAMES[Intrinsic.MUL]:
                if len(stack) < 2:
                    compiler_error_with_expansion_stack(token, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                a = stack.pop()
                b = stack.pop()
                stack.append(a * b)
            elif token.value == INTRINSIC_NAMES[Intrinsic.DIVMOD]:
                if len(stack) < 2:
                    compiler_error_with_expansion_stack(token, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                a = stack.pop()
                b = stack.pop()
                stack.append(b//a)
                stack.append(b%a)
            elif token.value == INTRINSIC_NAMES[Intrinsic.DROP]:
                if len(stack) < 1:
                    compiler_error_with_expansion_stack(token, f"not enough arguments for `{token.value}` intrinsic")
                    exit(1)
                stack.pop()
            elif token.value in macros:
                if token.expanded_count >= expansion_limit:
                    compiler_error_with_expansion_stack(token, "the macro exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                    exit(1)
                rtokens += reversed(expand_macro(macros[token.value], token))
            elif token.value in consts:
                stack.append(consts[token.value].value)
            else:
                compiler_error_with_expansion_stack(token, f"unsupported word `{token.value}` in compile time evaluation")
                exit(1)
        else:
            compiler_error_with_expansion_stack(token, f"{human(token.typ, HumanNumber.Plural)} are not supported in compile time evaluation")
            exit(1)
    if len(stack) != 1:
        compiler_error_with_expansion_stack(token, "The result of expression in compile time evaluation must be a single number")
        exit(1)
    return stack.pop()

def parse_program_from_tokens(tokens: List[Token], include_paths: List[str], expansion_limit: int) -> Program:
    stack: List[OpAddr] = []
    program: Program = Program(ops=[], memory_capacity=0)
    rtokens: List[Token] = list(reversed(tokens))
    macros: Dict[str, Macro] = {}
    memories: Dict[str, Memory] = {}
    procs: Dict[str, Proc] = {}
    consts: Dict[str, Const] = {}
    current_proc: Optional[Proc] = None
    iota: List[int] = [0]
    # TODO: consider getting rid of the ip variable in parse_program_from_tokens()
    ip: OpAddr = 0;
    while len(rtokens) > 0:
        token = rtokens.pop()
        assert len(TokenType) == 6, "Exhaustive token handling in parse_program_from_tokens"
        if token.typ == TokenType.WORD:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            if token.value in INTRINSIC_BY_NAMES:
                program.ops.append(Op(typ=OpType.INTRINSIC, token=token, operand=INTRINSIC_BY_NAMES[token.value]))
                ip += 1
            elif token.value in macros:
                if token.expanded_count >= expansion_limit:
                    compiler_error_with_expansion_stack(token, "the macro exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                    exit(1)
                rtokens += reversed(expand_macro(macros[token.value], token))
            elif current_proc is not None and token.value in current_proc.local_memories:
                program.ops.append(Op(typ=OpType.PUSH_LOCAL_MEM, token=token, operand=current_proc.local_memories[token.value].offset))
                ip += 1
            elif token.value in memories:
                program.ops.append(Op(typ=OpType.PUSH_MEM, token=token, operand=memories[token.value].offset))
                ip += 1
            elif token.value in procs:
                program.ops.append(Op(typ=OpType.CALL, token=token, operand=procs[token.value].addr))
                ip += 1
            elif token.value in consts:
                program.ops.append(Op(typ=OpType.PUSH_INT, token=token, operand=consts[token.value].value))
                ip += 1
            else:
                compiler_error_with_expansion_stack(token, "unknown word `%s`" % token.value)
                exit(1)
        elif token.typ == TokenType.INT:
            assert isinstance(token.value, int), "This could be a bug in the lexer"
            program.ops.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token))
            ip += 1
        elif token.typ == TokenType.STR:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            program.ops.append(Op(typ=OpType.PUSH_STR, operand=token.value, token=token));
            ip += 1
        elif token.typ == TokenType.CSTR:
            assert isinstance(token.value, str), "This could be a bug in the lexer"
            program.ops.append(Op(typ=OpType.PUSH_CSTR, operand=token.value, token=token));
            ip += 1
        elif token.typ == TokenType.CHAR:
            assert isinstance(token.value, int)
            program.ops.append(Op(typ=OpType.PUSH_INT, operand=token.value, token=token));
            ip += 1
        elif token.typ == TokenType.KEYWORD:
            assert len(Keyword) == 13, "Exhaustive keywords handling in parse_program_from_tokens()"
            if token.value == Keyword.IF:
                program.ops.append(Op(typ=OpType.IF, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.IFSTAR:
                if len(stack) == 0:
                    compiler_error_with_expansion_stack(token, '`if*` can only come after `else`')
                    exit(1)

                else_ip = stack[-1]
                if program.ops[else_ip].typ != OpType.ELSE:
                    compiler_error_with_expansion_stack(program.ops[else_ip].token, '`if*` can only come after `else`')
                    exit(1)
                program.ops.append(Op(typ=OpType.IFSTAR, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.ELSE:
                if len(stack) == 0:
                    compiler_error_with_expansion_stack(token, '`else` can only come after `if` or `if*`')
                    exit(1)

                if_ip = stack.pop()
                if program.ops[if_ip].typ == OpType.IF:
                    program.ops[if_ip].operand = ip + 1
                    stack.append(ip)
                    program.ops.append(Op(typ=OpType.ELSE, token=token))
                    ip += 1
                elif program.ops[if_ip].typ == OpType.IFSTAR:
                    else_before_ifstar_ip = None if len(stack) == 0 else stack.pop()
                    assert else_before_ifstar_ip is not None and program.ops[else_before_ifstar_ip].typ == OpType.ELSE, "At this point we should've already checked that `if*` comes after `else`. Otherwise this is a compiler bug."

                    program.ops[if_ip].operand = ip + 1
                    program.ops[else_before_ifstar_ip].operand = ip

                    stack.append(ip)
                    program.ops.append(Op(typ=OpType.ELSE, token=token))
                    ip += 1
                else:
                    compiler_error_with_expansion_stack(program.ops[if_ip].token, f'`else` can only come after `if` or `if*`')
                    exit(1)
            elif token.value == Keyword.END:
                block_ip = stack.pop()

                if program.ops[block_ip].typ == OpType.ELSE:
                    program.ops.append(Op(typ=OpType.END, token=token))
                    program.ops[block_ip].operand = ip
                    program.ops[ip].operand = ip + 1
                elif program.ops[block_ip].typ == OpType.DO:
                    program.ops.append(Op(typ=OpType.END, token=token))
                    assert program.ops[block_ip].operand is not None
                    while_ip = program.ops[block_ip].operand
                    assert isinstance(while_ip, OpAddr)

                    if program.ops[while_ip].typ != OpType.WHILE:
                        compiler_error_with_expansion_stack(program.ops[while_ip].token, '`end` can only close `do` blocks that are preceded by `while`')
                        exit(1)

                    program.ops[ip].operand = while_ip
                    program.ops[block_ip].operand = ip + 1
                elif program.ops[block_ip].typ == OpType.PREP_PROC:
                    assert current_proc is not None
                    program.ops[block_ip].operand = current_proc.local_memory_capacity
                    block_ip = stack.pop()
                    assert program.ops[block_ip].typ == OpType.SKIP_PROC
                    program.ops.append(Op(typ=OpType.RET, token=token, operand=current_proc.local_memory_capacity))
                    program.ops[block_ip].operand = ip + 1
                    current_proc = None
                elif program.ops[block_ip].typ == OpType.IFSTAR:
                    else_before_ifstar_ip = None if len(stack) == 0 else stack.pop()
                    assert else_before_ifstar_ip is not None and program.ops[else_before_ifstar_ip].typ == OpType.ELSE, "At this point we should've already checked that `if*` comes after `else`. Otherwise this is a compiler bug."

                    program.ops.append(Op(typ=OpType.END, token=token))
                    program.ops[block_ip].operand = ip
                    program.ops[else_before_ifstar_ip].operand = ip
                    program.ops[ip].operand = ip + 1
                elif program.ops[block_ip].typ == OpType.IF:
                    program.ops.append(Op(typ=OpType.END, token=token))
                    program.ops[block_ip].operand = ip
                    program.ops[ip].operand = ip + 1
                else:
                    # NOTE: the closing of `macro` blocks is handled in its own separate place, not here
                    compiler_error_with_expansion_stack(program.ops[block_ip].token, '`end` can only close `if`, `else`, `do`, `macro` or `proc` blocks for now')
                    exit(1)
                ip += 1
            elif token.value == Keyword.WHILE:
                program.ops.append(Op(typ=OpType.WHILE, token=token))
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.DO:
                program.ops.append(Op(typ=OpType.DO, token=token))
                if len(stack) == 0:
                    compiler_error_with_expansion_stack(token, "`do` is not preceded by `while`")
                    exit(1)
                while_ip = stack.pop()
                if program.ops[while_ip].typ != OpType.WHILE:
                    compiler_error_with_expansion_stack(token, "`do` is not preceded by `while`")
                    exit(1)
                program.ops[ip].operand = while_ip
                stack.append(ip)
                ip += 1
            elif token.value == Keyword.INCLUDE:
                if len(rtokens) == 0:
                    compiler_error_with_expansion_stack(token, "expected path to the include file but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.STR:
                    compiler_error_with_expansion_stack(token, "expected path to the include file to be %s but found %s" % (human(TokenType.STR), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                file_included = False
                for include_path in include_paths:
                    try:
                        if token.expanded_count >= expansion_limit:
                            compiler_error_with_expansion_stack(token, "the include exceeded the expansion limit (it expanded %d times)" % token.expanded_count)
                            exit(1)
                        rtokens += reversed(lex_file(path.join(include_path, token.value), token))
                        file_included = True
                        break
                    except FileNotFoundError:
                        continue
                if not file_included:
                    compiler_error_with_expansion_stack(token, "file `%s` not found" % token.value)
                    exit(1)
            elif token.value == Keyword.CONST:
                if len(rtokens) == 0:
                    compiler_error_with_expansion_stack(token, "expected const name but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.WORD:
                    compiler_error_with_expansion_stack(token, "expected const name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                const_name = token.value
                const_loc = token.loc
                check_word_redefinition(token, memories, macros, procs, consts)
                const_value = eval_const_value(rtokens, macros, consts, iota)
                consts[const_name] = Const(value=const_value, loc=const_loc)
            elif token.value == Keyword.MEMORY:

                if len(rtokens) == 0:
                    compiler_error_with_expansion_stack(token, "expected memory name but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.WORD:
                    compiler_error_with_expansion_stack(token, "expected memory name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                memory_name = token.value
                memory_loc = token.loc
                memory_size = eval_const_value(rtokens, macros, consts, iota)
                if current_proc is None:
                    check_word_redefinition(token, memories, macros, procs, consts)
                    memories[memory_name] = Memory(offset=program.memory_capacity, loc=memory_loc)
                    program.memory_capacity += memory_size
                else:
                    # TODO: local memory regions can shadow the global ones
                    # Is that something we actually want?
                    check_word_redefinition(token, current_proc.local_memories, macros, procs, consts)
                    current_proc.local_memories[memory_name] = Memory(offset=current_proc.local_memory_capacity, loc=memory_loc)
                    current_proc.local_memory_capacity += memory_size
            elif token.value == Keyword.MACRO:
                if len(rtokens) == 0:
                    compiler_error_with_expansion_stack(token, "expected macro name but found nothing")
                    exit(1)
                token = rtokens.pop()
                if token.typ != TokenType.WORD:
                    compiler_error_with_expansion_stack(token, "expected macro name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)))
                    exit(1)
                assert isinstance(token.value, str), "This is probably a bug in the lexer"
                check_word_redefinition(token, memories, macros, procs, consts)
                macro = Macro(token.loc, [])
                macros[token.value] = macro
                nesting_depth = 0
                while len(rtokens) > 0:
                    token = rtokens.pop()
                    if token.typ == TokenType.KEYWORD and token.value == Keyword.END and nesting_depth == 0:
                        break
                    else:
                        macro.tokens.append(token)
                        if token.typ == TokenType.KEYWORD:
                            assert len(Keyword) == 13, "Exhaustive handling of keywords in parsing macro body"
                            if token.value in [Keyword.IF, Keyword.WHILE, Keyword.MACRO, Keyword.MEMORY, Keyword.PROC, Keyword.CONST]:
                                nesting_depth += 1
                            elif token.value == Keyword.END:
                                nesting_depth -= 1
                if token.typ != TokenType.KEYWORD or token.value != Keyword.END:
                    compiler_error_with_expansion_stack(token, "expected `end` at the end of the macro definition but got `%s`" % (token.value, ))
                    exit(1)
            elif token.value == Keyword.PROC:
                if current_proc is None:
                    program.ops.append(Op(typ=OpType.SKIP_PROC, token=token))
                    proc_addr = ip

                    stack.append(ip)
                    ip += 1

                    program.ops.append(Op(typ=OpType.PREP_PROC, token=token))
                    stack.append(ip)
                    ip += 1

                    if len(rtokens) == 0:
                        compiler_error_with_expansion_stack(token, "expected procedure name but found nothing")
                        exit(1)
                    token = rtokens.pop()
                    if token.typ != TokenType.WORD:
                        compiler_error_with_expansion_stack(token, "expected procedure name to be %s but found %s" % (human(TokenType.WORD), human(token.typ)))
                        exit(1)
                    assert isinstance(token.value, str), "This is probably a bug in the lexer"
                    proc_loc = token.loc
                    proc_name = token.value
                    check_word_redefinition(token, memories, macros, procs, consts)
                    procs[proc_name] = Proc(addr=proc_addr + 1, loc=token.loc, local_memories={}, local_memory_capacity=0)
                    current_proc = procs[proc_name]
                else:
                    # TODO: forbid constant definition inside of proc
                    # TODO: forbid macro definition inside of proc
                    compiler_error_with_expansion_stack(token, "defining procedures inside of procedures is not allowed")
                    compiler_note(current_proc.loc, "the current procedure starts here")
            elif token.value in [Keyword.OFFSET, Keyword.RESET]:
                compiler_error_with_expansion_stack(token, f"keyword `{token.text}` is supported only in compile time evaluation context")
                exit(1)
            else:
                assert False, 'unreachable';
        else:
            assert False, 'unreachable'

    if len(stack) > 0:
        compiler_error_with_expansion_stack(program.ops[stack.pop()].token, 'unclosed block')
        exit(1)

    return program

def find_col(line: str, start: int, predicate: Callable[[str], bool]) -> int:
    while start < len(line) and not predicate(line[start]):
        start += 1
    return start

def unescape_string(s: str) -> str:
    # NOTE: unicode_escape assumes latin-1 encoding, so we kinda have
    # to do this weird round trip
    return s.encode('utf-8').decode('unicode_escape').encode('latin-1').decode('utf-8')

def find_string_literal_end(line: str, start: int) -> int:
    prev = line[start]
    while start < len(line):
        curr = line[start]
        if curr == '"' and prev != '\\':
            break
        prev = curr
        start += 1
    return start

def lex_lines(file_path: str, lines: List[str]) -> Generator[Token, None, None]:
    assert len(TokenType) == 6, 'Exhaustive handling of token types in lex_lines'
    row = 0
    str_literal_buf = ""
    while row < len(lines):
        line = lines[row]
        col = find_col(line, 0, lambda x: not x.isspace())
        col_end = 0
        while col < len(line):
            loc = (file_path, row + 1, col + 1)
            if line[col] == '"':
                while row < len(lines):
                    start = col
                    if str_literal_buf == "":
                        start += 1
                    else:
                        line = lines[row]
                    col_end = find_string_literal_end(line, start)
                    if col_end >= len(line) or line[col_end] != '"':
                        str_literal_buf += line[start:]
                        row +=1
                        col = 0
                    else:
                        str_literal_buf += line[start:col_end]
                        break
                if row >= len(lines):
                    compiler_error(loc, "unclosed string literal")
                    exit(1)
                assert line[col_end] == '"'
                col_end += 1
                text_of_token = str_literal_buf
                str_literal_buf = ""
                if col_end < len(line) and line[col_end] == 'c':
                    col_end += 1
                    yield Token(TokenType.CSTR, text_of_token, loc, unescape_string(text_of_token))
                else:
                    yield Token(TokenType.STR, text_of_token, loc, unescape_string(text_of_token))
                col = find_col(line, col_end, lambda x: not x.isspace())
            elif line[col] == "'":
                col_end = find_col(line, col+1, lambda x: x == "'")
                if col_end >= len(line) or line[col_end] != "'":
                    compiler_error(loc, "unclosed character literal")
                    exit(1)
                text_of_token = line[col+1:col_end]
                char_bytes = unescape_string(text_of_token).encode('utf-8')
                if len(char_bytes) != 1:
                    compiler_error(loc, "only a single byte is allowed inside of a character literal")
                    exit(1)
                yield Token(TokenType.CHAR, text_of_token, loc, char_bytes[0])
                col = find_col(line, col_end+1, lambda x: not x.isspace())
            else:
                col_end = find_col(line, col, lambda x: x.isspace())
                text_of_token = line[col:col_end]

                try:
                    yield Token(TokenType.INT, text_of_token, loc, int(text_of_token))
                except ValueError:
                    if text_of_token in KEYWORD_BY_NAMES:
                        yield Token(TokenType.KEYWORD, text_of_token, loc, KEYWORD_BY_NAMES[text_of_token])
                    else:
                        # TODO: `69//` is recognized as a single word
                        # And not a number plus a comment
                        if text_of_token.startswith("//"):
                            break
                        yield Token(TokenType.WORD, text_of_token, loc, text_of_token)
                col = find_col(line, col_end, lambda x: not x.isspace())
        row += 1

def lex_file(file_path: str, expanded_from: Optional[Token] = None) -> List[Token]:
    with open(file_path, "r", encoding='utf-8') as f:
        result = [token for token in lex_lines(file_path, f.readlines())]
        for token in result:
            if expanded_from is not None:
                token.expanded_from = expanded_from
                token.expanded_count = expanded_from.expanded_count + 1
        return result

def parse_program_from_file(file_path: str, include_paths: List[str], expansion_limit: int) -> Program:
    return parse_program_from_tokens(lex_file(file_path), include_paths, expansion_limit)

def cmd_call_echoed(cmd: List[str], silent: bool) -> int:
    if not silent:
        print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.call(cmd)

# TODO: with a lot of procs the control flow graphs becomes useless even on small programs
# Maybe we should eliminate unreachable code or something
# TODO: test.py never touches generate_control_flow_graph_as_dot_file
# Which leads to constantly forgetting to update the implementation
def generate_control_flow_graph_as_dot_file(program: Program, dot_path: str):
    with open(dot_path, "w") as f:
        f.write("digraph Program {\n")
        assert len(OpType) == 16, f"Exhaustive handling of OpType in generate_control_flow_graph_as_dot_file(), {len(OpType)}"
        for ip in range(len(program.ops)):
            op = program.ops[ip]
            if op.typ == OpType.INTRINSIC:
                assert isinstance(op.operand, Intrinsic)
                f.write(f"    Node_{ip} [label={repr(repr(INTRINSIC_NAMES[op.operand]))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_STR:
                assert isinstance(op.operand, str)
                f.write(f"    Node_{ip} [label={repr(repr(op.operand))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_CSTR:
                assert isinstance(op.operand, str)
                f.write(f"    Node_{ip} [label={repr(repr(op.operand))}];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_INT:
                assert isinstance(op.operand, int)
                f.write(f"    Node_{ip} [label={op.operand}]\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_MEM:
                assert isinstance(op.operand, int)
                f.write(f"    Node_{ip} [label=\"mem({op.operand})\"]\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.PUSH_LOCAL_MEM:
                assert isinstance(op.operand, int)
                f.write(f"    Node_{ip} [label=\"local_mem({op.operand})\"]\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ in [OpType.IF, OpType.IFSTAR]:
                assert isinstance(op.operand, OpAddr), f"{op.operand}"
                f.write(f"    Node_{ip} [shape=record label=if];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1} [label=true];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand} [label=false style=dashed];\n")
            elif op.typ == OpType.WHILE:
                f.write(f"    Node_{ip} [shape=record label=while];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.DO:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=do];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1} [label=true];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand} [label=false style=dashed];\n")
            elif op.typ == OpType.ELSE:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=else];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            elif op.typ == OpType.END:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=end];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            elif op.typ == OpType.SKIP_PROC:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=skip_proc];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
            elif op.typ == OpType.PREP_PROC:
                f.write(f"    Node_{ip} [shape=record label=prep_proc];\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            elif op.typ == OpType.RET:
                f.write(f"    Node_{ip} [shape=record label=ret];\n")
            elif op.typ == OpType.CALL:
                assert isinstance(op.operand, OpAddr)
                f.write(f"    Node_{ip} [shape=record label=call];\n")
                f.write(f"    Node_{ip} -> Node_{op.operand};\n")
                f.write(f"    Node_{ip} -> Node_{ip + 1};\n")
            else:
                assert False, f"unimplemented operation {op.typ}"
        f.write(f"    Node_{len(program.ops)} [label=halt];\n")
        f.write("}\n")

def usage(compiler_name: str):
    print("Usage: %s [OPTIONS] <SUBCOMMAND> [ARGS]" % compiler_name)
    print("  OPTIONS:")
    print("    -debug                Enable debug mode.")
    print("    -I <path>             Add the path to the include search list")
    print("    -E <expansion-limit>  Macro and include expansion limit. (Default %d)" % DEFAULT_EXPANSION_LIMIT)
    print("    -unsafe               Disable type checking.")
    print("  SUBCOMMAND:")
    print("    sim <file>            Simulate the program")
    print("    com [OPTIONS] <file>  Compile the program")
    print("      OPTIONS:")
    print("        -r                  Run the program after successful compilation")
    print("        -o <file|dir>       Customize the output path")
    print("        -s                  Silent mode. Don't print any info about compilation phases.")
    print("        -cf                 Dump Control Flow graph of the program in a dot format.")
    print("    help                  Print this help to stdout and exit with 0 code")

if __name__ == '__main__' and '__file__' in globals():
    argv = sys.argv
    assert len(argv) >= 1
    compiler_name, *argv = argv

    include_paths = ['.', './std/']
    expansion_limit = DEFAULT_EXPANSION_LIMIT
    unsafe = False

    while len(argv) > 0:
        if argv[0] == '-debug':
            argv = argv[1:]
            debug = True
        elif argv[0] == '-I':
            argv = argv[1:]
            if len(argv) == 0:
                usage(compiler_name)
                print("[ERROR] no path is provided for `-I` flag", file=sys.stderr)
                exit(1)
            include_path, *argv = argv
            include_paths.append(include_path)
        elif argv[0] == '-E':
            argv = argv[1:]
            if len(argv) == 0:
                usage(compiler_name)
                print("[ERROR] no value is provided for `-E` flag", file=sys.stderr)
                exit(1)
            arg, *argv = argv
            expansion_limit = int(arg)
        elif argv[0] == '-unsafe':
            argv = argv[1:]
            unsafe = True
        else:
            break

    if len(argv) < 1:
        usage(compiler_name)
        print("[ERROR] no subcommand is provided", file=sys.stderr)
        exit(1)
    subcommand, *argv = argv

    program_path: Optional[str] = None

    if subcommand == "sim":
        if len(argv) < 1:
            usage(compiler_name)
            print("[ERROR] no input file is provided for the simulation", file=sys.stderr)
            exit(1)
        program_path, *argv = argv
        include_paths.append(path.dirname(program_path))
        program = parse_program_from_file(program_path, include_paths, expansion_limit);
        if not unsafe:
            type_check_program(program)
        simulate_little_endian_linux(program, [program_path] + argv)
    elif subcommand == "com":
        silent = False
        control_flow = False
        run = False
        output_path = None
        while len(argv) > 0:
            arg, *argv = argv
            if arg == '-r':
                run = True
            elif arg == '-s':
                silent = True
            elif arg == '-o':
                if len(argv) == 0:
                    usage(compiler_name)
                    print("[ERROR] no argument is provided for parameter -o", file=sys.stderr)
                    exit(1)
                output_path, *argv = argv
            elif arg == '-cf':
                control_flow = True
            else:
                program_path = arg
                break

        if program_path is None:
            usage(compiler_name)
            print("[ERROR] no input file is provided for the compilation", file=sys.stderr)
            exit(1)

        basename = None
        basedir = None
        if output_path is not None:
            if path.isdir(output_path):
                basename = path.basename(program_path)
                if basename.endswith(PORTH_EXT):
                    basename = basename[:-len(PORTH_EXT)]
                basedir = path.dirname(output_path)
            else:
                basename = path.basename(output_path)
                basedir = path.dirname(output_path)
        else:
            basename = path.basename(program_path)
            if basename.endswith(PORTH_EXT):
                basename = basename[:-len(PORTH_EXT)]
            basedir = path.dirname(program_path)

        # if basedir is empty we should "fix" the path appending the current working directory.
        # So we avoid `com -r` to run command from $PATH.
        if basedir == "":
            basedir = os.getcwd()
        basepath = path.join(basedir, basename)

        include_paths.append(path.dirname(program_path))

        program = parse_program_from_file(program_path, include_paths, expansion_limit);
        if control_flow:
            dot_path = basepath + ".dot"
            if not silent:
                print(f"[INFO] Generating {dot_path}")
            generate_control_flow_graph_as_dot_file(program, dot_path)
            cmd_call_echoed(["dot", "-Tsvg", "-O", dot_path], silent)
        if not unsafe:
            type_check_program(program)
        if not silent:
            print("[INFO] Generating %s" % (basepath + ".asm"))
        generate_nasm_linux_x86_64(program, basepath + ".asm")
        cmd_call_echoed(["nasm", "-felf64", basepath + ".asm"], silent)
        cmd_call_echoed(["ld", "-o", basepath, basepath + ".o"], silent)
        if run:
            exit(cmd_call_echoed([basepath] + argv, silent))
    elif subcommand == "help":
        usage(compiler_name)
        exit(0)
    else:
        usage(compiler_name)
        print("[ERROR] unknown subcommand %s" % (subcommand), file=sys.stderr)
        exit(1)
