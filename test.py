#!/usr/bin/env python3

import sys
import os
import subprocess
import shlex

def cmd_run_echoed(cmd, **kwargs):
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.run(cmd, **kwargs)

def test(folder):
    sim_failed = 0
    com_failed = 0
    for entry in os.scandir(folder):
        porth_ext = '.porth'
        if entry.is_file() and entry.path.endswith(porth_ext):
            print('[INFO] Testing %s' % entry.path)

            bin_path = entry.path[:-len(porth_ext)] + ".bin"
            expected_output = None
            with open(bin_path, "rb") as f:
                bin_file = f.read()
                index = 0
                expected_returncode = int.from_bytes(bin_file[index:index + 1], byteorder='little')
                index += 1
                expected_output_length = int.from_bytes(bin_file[index:index + 8], byteorder='little')
                index += 8
                expected_output = bin_file[index:index + expected_output_length]
                index += expected_output_length
                expected_error_length = int.from_bytes(bin_file[index:index + 8], byteorder='little')
                index += 8
                expected_error = bin_file[index:index + expected_error_length]

            sim_cmd = cmd_run_echoed(["./porth.py", "sim", entry.path], capture_output=True)
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

            com_cmd = cmd_run_echoed(["./porth.py", "com", "-r", "-s", entry.path], capture_output=True)
            com_returncode = com_cmd.returncode
            com_output = com_cmd.stdout
            com_error = com_cmd.stderr
            if com_returncode != expected_returncode or com_output != expected_output or com_error != expected_error:
                com_failed += 1
                print("[ERROR] Unexpected compilation output")
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

def record(folder, mode='sim'):
    for entry in os.scandir(folder):
        porth_ext = '.porth'
        if entry.is_file() and entry.path.endswith(porth_ext):
            if mode == 'sim':
                output = cmd_run_echoed(["./porth.py", "sim", entry.path], capture_output=True)
            elif mode == 'com':
                output = cmd_run_echoed(["./porth.py", "com", "-r", "-s", entry.path], capture_output=True)
            else:
                print("[ERROR] Unknown record mode `%s`" % mode)
                exit(1)
            bin_path = entry.path[:-len(porth_ext)] + ".bin"
            print("[INFO] Saving output to %s" % bin_path)
            with open(bin_path, "wb") as bin_file:
                bin_file.write(
                    output.returncode.to_bytes(1, byteorder="little")
                    + len(output.stdout).to_bytes(8, byteorder="little")
                    + output.stdout
                    + len(output.stderr).to_bytes(8, byteorder="little")
                    + output.stderr
                )

def usage(exe_name):
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
