#!/usr/bin/env python3

import sys
import os
import subprocess
import shlex

def cmd_run_echoed(cmd, **kwargs):
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    cmd = subprocess.run(cmd, **kwargs)
    if cmd.returncode != 0:
        print(cmd.stdout.decode('utf-8'), file=sys.stdout)
        print(cmd.stderr.decode('utf-8'), file=sys.stderr)
        exit(cmd.returncode)
    return cmd

def test(folder):
    sim_failed = 0
    com_failed = 0
    for entry in os.scandir(folder):
        porth_ext = '.porth'
        if entry.is_file() and entry.path.endswith(porth_ext):
            print('[INFO] Testing %s' % entry.path)

            txt_path = entry.path[:-len(porth_ext)] + ".txt"
            expected_output = None
            with open(txt_path, "rb") as f:
                expected_output = f.read()

            sim_output = cmd_run_echoed(["./porth.py", "sim", entry.path], capture_output=True).stdout
            if sim_output != expected_output:
                sim_failed += 1
                print("[ERROR] Unexpected simulation output")
                print("  Expected:")
                print("    %s" % expected_output)
                print("  Actual:")
                print("    %s" % sim_output)
                # exit(1)

            com_output = cmd_run_echoed(["./porth.py", "com", "-r", "-s", entry.path], capture_output=True).stdout
            if com_output != expected_output:
                com_failed += 1
                print("[ERROR] Unexpected compilation output")
                print("  Expected:")
                print("    %s" % expected_output)
                print("  Actual:")
                print("    %s" % com_output)
                # exit(1)
    print()
    print("Simulation failed: %d, Compilation failed: %d" % (sim_failed, com_failed))
    if sim_failed != 0 or com_failed != 0:
        exit(1)

def record(folder, mode='sim'):
    for entry in os.scandir(folder):
        porth_ext = '.porth'
        if entry.is_file() and entry.path.endswith(porth_ext):
            output = ""
            if mode == 'sim':
                output = cmd_run_echoed(["./porth.py", "sim", entry.path], capture_output=True).stdout
            elif mode == 'com':
                output = cmd_run_echoed(["./porth.py", "com", "-r", "-s", entry.path], capture_output=True).stdout
            else:
                print("[ERROR] Unknown record mode `%s`" % mode)
                exit(1)
            txt_path = entry.path[:-len(porth_ext)] + ".txt"
            print("[INFO] Saving output to %s" % txt_path)
            with open(txt_path, "wb") as txt_file:
                txt_file.write(output)

def usage(exe_name):
    print("Usage: ./test.py [OPTIONS] [SUBCOMMAND]")
    print("OPTIONS:")
    print("    -f <folder>   Folder with the tests. (Default: ./tests/)")
    print("SUBCOMMANDS:")
    print("    test             Run the tests. (Default when no subcommand is provided)")
    print("    record [-com]    Record expected output of the tests.")
    print("    help             Print this message to stdout and exit with 0 code.")

# TODO: test compiler errors
#
# It would be better if we had a different format for expected
# outcomes of the test cases instead of just plan text files with
# stdout.
#
# Something like a custom file format that contains:
#
# 1. Expected returncode
# 2. Expected stdout
# 3. Expected stderr
#
# This will simplify recording and replaying test cases and reduce the
# amount of required flags.
#
# We could use something like JSON, but in a long term I plan to
# rewrite test.py in Porth too, so it has to be something that is easy
# to parse even in such a spartan language as Porth.
#
# I'm thinking about a simple binary format:
#
# ```
# |1 byte -- expected return code|
# |8 bytes -- length of stdout|
# |len(stdout) bytes -- the expected stdout encoded as UTF-8|
# |8 bytes -- length of stderr|
# |len(stderr) bytes -- the expected stderr encoded as UTF-8|
# ```
#
# Such format is easy to produce/parse in both Porth and Python (using
# the bytes).
#
# Using binary format will also enable us to assert binary outputs of
# the test programs. For instances, PPM pictures.

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
