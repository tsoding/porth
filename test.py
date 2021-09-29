#!/usr/bin/env python3

import sys
import os
import subprocess
import shlex
from typing import List, BinaryIO, Tuple
from dataclasses import dataclass

def cmd_run_echoed(cmd, **kwargs):
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.run(cmd, **kwargs)

def read_blob_field(f: BinaryIO, name: bytes) -> bytes:
    line = f.readline()
    field = b':b ' + name + b' '
    assert line.startswith(field)
    assert line.endswith(b'\n')
    size = int(line[len(field):-1])
    blob = f.read(size)
    assert f.read(1) == b'\n'
    return blob

def read_int_field(f: BinaryIO, name: bytes) -> int:
    line = f.readline()
    field = b':i ' + name + b' '
    assert line.startswith(field)
    assert line.endswith(b'\n')
    return int(line[len(field):-1])

def write_int_field(f: BinaryIO, name: bytes, value: int):
    f.write(b':i %s %d\n' % (name, value))

def write_blob_field(f: BinaryIO, name: bytes, blob: bytes):
    f.write(b':b %s %d\n' % (name, len(blob)))
    f.write(blob)
    f.write(b'\n')

@dataclass
class TestCase:
    argv: List[bytes]
    stdin: bytes
    returncode: int
    stdout: bytes
    stderr: bytes

def load_test_case(file_path: str) -> TestCase:
    with open(file_path, "rb") as f:
        argv = []
        argc = read_int_field(f, b'argc')
        for index in range(argc):
            argv.append(read_blob_field(f, b'arg%d' % index))
        stdin = read_blob_field(f, b'stdin')
        returncode = read_int_field(f, b'returncode')
        stdout = read_blob_field(f, b'stdout')
        stderr = read_blob_field(f, b'stderr')
        return TestCase(argv, stdin, returncode, stdout, stderr)

def save_test_case(file_path: str,
                   argv: List[bytes], stdin: bytes,
                   returncode: int, stdout: bytes, stderr: bytes):
    with open(file_path, "wb") as f:
        write_int_field(f, b'argc', len(argv))
        for index, arg in enumerate(argv):
            write_blob_field(f, b'arg%d' % index, arg)
        write_blob_field(f, b'stdin', stdin)
        write_int_field(f, b'returncode', returncode)
        write_blob_field(f, b'stdout', stdout)
        write_blob_field(f, b'stderr', stderr)

def test(folder: str):
    sim_failed = 0
    com_failed = 0
    for entry in os.scandir(folder):
        porth_ext = '.porth'
        if entry.is_file() and entry.path.endswith(porth_ext):
            print('[INFO] Testing %s' % entry.path)

            txt_path = entry.path[:-len(porth_ext)] + ".txt"
            tc = load_test_case(txt_path)

            sim = cmd_run_echoed([sys.executable, "./porth.py", "-I", folder, "sim", entry.path], capture_output=True)
            if sim.returncode != tc.returncode or sim.stdout != tc.stdout or sim.stderr != tc.stderr:
                sim_failed += 1
                print("[ERROR] Unexpected simulation output")
                print("  Expected:")
                print("    return code: %s" % tc.returncode)
                print("    stdout: %s" % tc.stdout.decode("utf-8"))
                print("    stderr: %s" % tc.stderr.decode("utf-8"))
                print("  Actual:")
                print("    return code: %s" % sim.returncode)
                print("    stdout: %s" % sim.stdout.decode("utf-8"))
                print("    stderr: %s" % sim.stderr.decode("utf-8"))

            com = cmd_run_echoed([sys.executable, "./porth.py", "-I", folder, "com", "-r", "-s", entry.path], capture_output=True)
            if com.returncode != tc.returncode or com.stdout != tc.stdout or com.stderr != tc.stderr:
                com_failed += 1
                print("[ERROR] Unexpected compilation output")
                print("  Expected:")
                print("    return code: %s" % tc.returncode)
                print("    stdout: %s" % tc.stdout.decode("utf-8"))
                print("    stderr: %s" % tc.stderr.decode("utf-8"))
                print("  Actual:")
                print("    return code: %s" % com.returncode)
                print("    stdout: %s" % com.stdout.decode("utf-8"))
                print("    stderr: %s" % com.stderr.decode("utf-8"))
    print()
    print("Simulation failed: %d, Compilation failed: %d" % (sim_failed, com_failed))
    if sim_failed != 0 or com_failed != 0:
        exit(1)

def record(folder: str, mode: str='sim'):
    for entry in os.scandir(folder):
        porth_ext = '.porth'
        if entry.is_file() and entry.path.endswith(porth_ext):
            if mode == 'sim':
                output = cmd_run_echoed([sys.executable, "./porth.py", "-I", folder, "sim", entry.path], capture_output=True)
            elif mode == 'com':
                output = cmd_run_echoed([sys.executable, "./porth.py", "-I", folder, "com", "-r", "-s", entry.path], capture_output=True)
            else:
                print("[ERROR] Unknown record mode `%s`" % mode)
                exit(1)
            txt_path = entry.path[:-len(porth_ext)] + ".txt"
            print("[INFO] Saving output to %s" % txt_path)
            # TODO: there is no way to record the test case input
            save_test_case(txt_path, [], b"", output.returncode, output.stdout, output.stderr)

def usage(exe_name: str):
    print("Usage: ./test.py [OPTIONS] [SUBCOMMAND]")
    print("OPTIONS:")
    print("    -f <folder>   Folder with the tests. (Default: ./tests/)")
    print("SUBCOMMANDS:")
    print("    test             Run the tests. (Default when no subcommand is provided)")
    print("    record [-com]    Record expected output of the tests.")
    print("    help             Print this message to stdout and exit with 0 code.")

if __name__ == '__main__':
    exe_name, *argv = sys.argv

    folder = "./tests/"
    subcmd = "test"

    while len(argv) > 0:
        arg, *argv = argv
        if arg == '-f':
            if len(argv) == 0:
                print("[ERROR] no <folder> is provided for option `-f`")
                exit(1)
            folder, *argv = argv
        else:
            subcmd = arg
            break

    if subcmd == 'record':
        mode = 'sim'
        while len(argv) > 0:
            arg, *argv = argv
            if arg == '-com':
                mode = 'com'
            else:
                print("[ERROR] unknown flag `%s`" % arg)
                exit(1)
        record(folder, mode)
    elif subcmd == 'test':
        test(folder)
    elif subcmd == 'help':
        usage(exe_name)
    else:
        usage(exe_name)
        print("[ERROR] unknown subcommand `%s`" % subcmd, file=sys.stderr)
        exit(1);
