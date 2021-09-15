#!/usr/bin/env python3

import sys
import os
import subprocess
import shlex

def cmd_run_echoed(cmd, **kwargs):
    print("[CMD] %s" % " ".join(map(shlex.quote, cmd)))
    return subprocess.run(cmd, **kwargs)

def test():
    sim_failed = 0
    com_failed = 0
    for entry in os.scandir("./tests/"):
        porth_ext = '.porth'
        if entry.is_file() and entry.path.endswith(porth_ext):
            print('[INFO] Testing %s' % entry.path)

            txt_path = entry.path[:-len(porth_ext)] + ".txt"
            expected_output = None
            with open(txt_path, "rb") as f:
                expected_output = f.read()

            sim_output = cmd_run_echoed(["./porth.py", "sim", entry.path], capture_output=True, check=True).stdout
            if sim_output != expected_output:
                sim_failed += 1
                print("[ERROR] Unexpected simulation output")
                print("  Expected:")
                print("    %s" % expected_output)
                print("  Actual:")
                print("    %s" % sim_output)
                # exit(1)

            cmd_run_echoed(["./porth.py", "com", entry.path], check=True)
            com_output = cmd_run_echoed([entry.path[:-len(porth_ext)]], capture_output=True, check=True).stdout
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

def record():
    for entry in os.scandir("./tests/"):
        porth_ext = '.porth'
        if entry.is_file() and entry.path.endswith(porth_ext):
            sim_output = cmd_run_echoed(["./porth.py", "sim", entry.path], capture_output=True, check=True).stdout
            txt_path = entry.path[:-len(porth_ext)] + ".txt"
            print("[INFO] Saving output to %s" % txt_path)
            with open(txt_path, "wb") as txt_file:
                txt_file.write(sim_output)

def usage(exe_name):
    print("Usage: ./test.py [SUBCOMMAND]")
    print("SUBCOMMANDS:")
    print("    test          Run the tests. (Default when no subcommand is provided)")
    print("    record        Record expected output of the tests.")
    print("    help          Print this message to stdout and exit with 0 code.")

if __name__ == '__main__':
    exe_name, *argv = sys.argv

    if len(argv) == 0:
        test()
    else:
        subcmd, *argv = argv
        if subcmd == 'record':
            record()
        elif subcmd == 'test':
            test()
        elif subcmd == 'help':
            usage(exe_name)
        else:
            usage(exe_name)
            print("[ERROR] unknown subcommand `%s`" % subcmd, file=sys.stderr)
            exit(1);
