#!/usr/bin/env python3

import sys
import os
import subprocess
import shlex
from typing import BinaryIO, Tuple

def cmd_run_echoed(cmd, **kwargs):
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.run(cmd, **kwargs)

def read_field(f: BinaryIO, name: bytes) -> bytes:
    line = f.readline()
    field = b': ' + name + b' '
    assert line.startswith(field)
    assert line.endswith(b'\n')
    return line[len(field):-1]

def load_test_case(file_path: str) -> Tuple[int, bytes, bytes]:
    with open(file_path, "rb") as f:
        returncode = int(read_field(f, b'returncode'))
        stdout_len = int(read_field(f, b'stdout'))
        stdout = f.read(stdout_len)
        assert f.read(1) == b'\n'
        stderr_len = int(read_field(f, b'stderr'))
        stderr = f.read(stderr_len)
        assert f.read(1) == b'\n'
        return (returncode, stdout, stderr)

def save_test_case(file_path: str, returncode: int, stdout: bytes, stderr: bytes):
    with open(file_path, "wb") as f:
        f.write(b": returncode %d\n" % returncode)
        f.write(b": stdout %d\n" % len(stdout))
        f.write(stdout)
        f.write(b"\n")
        f.write(b": stderr %d\n" % len(stderr))
        f.write(stderr)
        f.write(b"\n")

def test(folder: str):
    sim_failed = 0
    com_failed = 0
    arch_list = ["x86_64", "aarch64"]

    for arch in arch_list:
        for entry in os.scandir(folder):
            porth_ext = '.porth'
            if entry.is_file() and entry.path.endswith(porth_ext):
                print('[INFO] Testing %s for arch %s' % (entry.path, arch))

                txt_path = entry.path[:-len(porth_ext)] + ".txt"
                (expected_returncode, expected_output, expected_error) = load_test_case(txt_path)

                sim_cmd = cmd_run_echoed([sys.executable, "./porth.py", "-I", folder, "sim", entry.path], capture_output=True)
                sim_returncode = sim_cmd.returncode
                sim_output = sim_cmd.stdout
                sim_error = sim_cmd.stderr
                if sim_returncode != expected_returncode or sim_output != expected_output or sim_error != expected_error:
                    sim_failed += 1
                    print("[ERROR] Unexpected simulation output")
                    print("  Expected:")
                    print("    return code: %s" % expected_returncode)
                    print("    stdout: %s" % expected_output.decode("utf-8"))
                    print("    stderr: %s" % expected_error.decode("utf-8"))
                    print("  Actual:")
                    print("    return code: %s" % sim_returncode)
                    print("    stdout: %s" % sim_output.decode("utf-8"))
                    print("    stderr: %s" % sim_error.decode("utf-8"))

                com_cmd = cmd_run_echoed([sys.executable, "./porth.py", "-ARCH", arch, "-I", folder, "com", "-r", "-s", entry.path], capture_output=True)
                com_returncode = com_cmd.returncode
                com_output = com_cmd.stdout
                com_error = com_cmd.stderr
                if com_returncode != expected_returncode or com_output != expected_output or com_error != expected_error:
                    com_failed += 1
                    print("[ERROR] Unexpected compilation output for arch %s" % arch)
                    print("  Expected:")
                    print("    return code: %s" % expected_returncode)
                    print("    stdout: %s" % expected_output.decode("utf-8"))
                    print("    stderr: %s" % expected_error.decode("utf-8"))
                    print("  Actual:")
                    print("    return code: %s" % com_returncode)
                    print("    stdout: %s" % com_output.decode("utf-8"))
                    print("    stderr: %s" % com_error.decode("utf-8"))
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
            save_test_case(txt_path, output.returncode, output.stdout, output.stderr)

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
