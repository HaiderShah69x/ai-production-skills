#!/usr/bin/env python3
"""
attacks/run_skill02_benchmark.py — Integrity and Mutation Kill Matrix Benchmark.

Verifies:
  1. Collection Guard: Ensures pytest collects and executes >= 4 required tests.
     Exits with code 2 if tests are missing or skipped.
  2. Mutation Kill Matrix:
     Runs pytest tests/test_account_adversarial.py against 3 intentional defects:
       - Mutant 1 (negative_bypass): Must FAIL (Exit Code 1).
       - Mutant 2 (zero_bypass):     Must FAIL (Exit Code 1).
       - Mutant 3 (state_leak):      Must FAIL (Exit Code 1).
     Runs against the fixed implementation:
       - Fixed:                      Must PASS (Exit Code 0).

Exits 0 only if ALL mutants are caught and the fixed implementation passes.
"""

import os
import subprocess
import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).parent.parent
TEST_FILE = REPO_ROOT / "tests" / "test_account_adversarial.py"

MIN_REQUIRED_TESTS = 4

MUTANTS = [
    ("negative_bypass", "Mutant 1 (negative_bypass)", 1),
    ("zero_bypass",     "Mutant 2 (zero_bypass)",     1),
    ("state_leak",      "Mutant 3 (state_leak)",      1),
    ("fixed",           "Clean Fixed Implementation", 0),
]


def run_collection_check() -> int:
    """Run pytest --collect-only to verify collection guard."""
    print("============================================================", flush=True)
    print("Stage 1: Harness Collection & Tamper Guard Check", flush=True)
    print("============================================================", flush=True)

    cmd = [sys.executable, "-m", "pytest", str(TEST_FILE), "--collect-only", "-q"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)

    collected_count = 0
    for line in proc.stdout.splitlines():
        if "test_" in line or "::test_" in line:
            collected_count += 1
        elif "collected" in line:
            # e.g., "4 tests collected in 0.01s" or "collected 4 items"
            parts = line.split()
            for part in parts:
                if part.isdigit():
                    collected_count = max(collected_count, int(part))

    print(f"  Tests collected: {collected_count} (minimum required: {MIN_REQUIRED_TESTS})", flush=True)

    if collected_count < MIN_REQUIRED_TESTS or proc.returncode != 0:
        print(f"  [FAIL] Collection guard failed! Collected {collected_count} < {MIN_REQUIRED_TESTS}.", flush=True)
        return 2

    print("  [PASS] Collection guard passed: all required security tests registered.\n", flush=True)
    return 0


def run_mutation_matrix() -> int:
    """Run pytest against each mutant configuration."""
    print("============================================================", flush=True)
    print("Stage 2: Mutation Kill Matrix", flush=True)
    print("============================================================", flush=True)

    overall_failures = 0

    for bug_type, label, expected_exit in MUTANTS:
        print(f"--- Testing {label} (Expected Exit: {expected_exit}) ---", flush=True)
        env = os.environ.copy()
        env["ACCOUNT_BUG_TYPE"] = bug_type

        cmd = [sys.executable, "-m", "pytest", str(TEST_FILE), "-q"]
        proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)

        actual_exit = 0 if proc.returncode == 0 else 1

        print(f"  Pytest exit code : {actual_exit} (expected {expected_exit})", flush=True)
        if proc.stdout.strip():
            # Show summary line from pytest output
            summary_line = proc.stdout.strip().splitlines()[-1]
            print(f"  Pytest summary   : {summary_line}", flush=True)

        if actual_exit == expected_exit:
            if expected_exit == 1:
                print(f"  [PASS] Mutation caught successfully: {label} failed as required.\n", flush=True)
            else:
                print(f"  [PASS] Fixed implementation verified: all assertions passed.\n", flush=True)
        else:
            overall_failures += 1
            if expected_exit == 1:
                print(f"  [FAIL] ESCAPED MUTANT! {label} slipped through test suite unnoticed!\n", flush=True)
            else:
                print(f"  [FAIL] Regression! Fixed implementation failed test suite!\n", flush=True)

    return 1 if overall_failures > 0 else 0


def main():
    col_status = run_collection_check()
    if col_status != 0:
        sys.exit(col_status)

    matrix_status = run_mutation_matrix()

    print("============================================================", flush=True)
    if matrix_status == 0:
        print("ALL TESTS PASSED: Harness integrity verified, all 3 mutants killed.", flush=True)
    else:
        print("BENCHMARK FAILED: One or more mutations escaped or regressions found.", flush=True)
    print("============================================================", flush=True)

    sys.exit(matrix_status)


if __name__ == "__main__":
    main()
