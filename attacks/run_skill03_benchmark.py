#!/usr/bin/env python3
"""
attacks/run_skill03_benchmark.py — Benchmark runner for untrusted-boundaries-and-auth.

Stages:
  Stage 1: Collection Guard Check (asserts >= 8 security tests collected)
  Stage 2: Execution against VulnerableDocumentService (Must FAIL with exit code 1)
  Stage 3: Execution against HardenedDocumentService (Must PASS with exit code 0)
"""

import os
import subprocess
import sys
import pathlib

REPO_ROOT = pathlib.Path(__file__).parent.parent
TEST_FILE = REPO_ROOT / "tests" / "test_auth_adversarial.py"
MIN_REQUIRED_TESTS = 6


def run_collection_check() -> int:
    print("============================================================", flush=True)
    print("Stage 1: Collection & Tamper Guard Check", flush=True)
    print("============================================================", flush=True)

    cmd = [sys.executable, "-m", "pytest", str(TEST_FILE), "--collect-only", "-q"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)

    collected_count = 0
    for line in proc.stdout.splitlines():
        if "test_" in line or "::test_" in line:
            collected_count += 1
        elif "collected" in line:
            parts = line.split()
            for part in parts:
                if part.isdigit():
                    collected_count = max(collected_count, int(part))

    print(f"  Tests collected: {collected_count} (minimum required: {MIN_REQUIRED_TESTS})", flush=True)

    if collected_count < MIN_REQUIRED_TESTS or proc.returncode != 0:
        print(f"  [FAIL] Collection guard failed! {collected_count} < {MIN_REQUIRED_TESTS}", flush=True)
        return 2

    print("  [PASS] Collection guard passed: all security boundaries covered.\n", flush=True)
    return 0


def run_test_target(impl_name: str, expected_exit: int) -> int:
    env = os.environ.copy()
    env["AUTH_SERVICE_IMPL"] = impl_name

    cmd = [sys.executable, "-m", "pytest", str(TEST_FILE), "-v", "-q"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)

    actual_exit = 0 if proc.returncode == 0 else 1

    print(f"  Target implementation: {impl_name}", flush=True)
    print(f"  Pytest exit code     : {actual_exit} (expected {expected_exit})", flush=True)
    if proc.stdout.strip():
        summary_line = proc.stdout.strip().splitlines()[-1]
        print(f"  Pytest summary       : {summary_line}", flush=True)

    if actual_exit == expected_exit:
        if expected_exit == 1:
            print(f"  [PASS] Vulnerability caught: {impl_name} failed security tests as expected.\n", flush=True)
        else:
            print(f"  [PASS] Hardened verified: {impl_name} passed all security assertions.\n", flush=True)
        return 0
    else:
        if expected_exit == 1:
            print(f"  [FAIL] Uncaught vulnerability! {impl_name} unexpectedly passed security tests!\n", flush=True)
        else:
            print(f"  [FAIL] Regression! {impl_name} failed security tests!\n", flush=True)
            # Print verbose output to help diagnose
            if proc.stdout.strip():
                print("  --- Pytest stdout ---", flush=True)
                for line in proc.stdout.strip().splitlines():
                    print(f"    {line}", flush=True)
            if proc.stderr.strip():
                print("  --- Pytest stderr ---", flush=True)
                for line in proc.stderr.strip().splitlines():
                    print(f"    {line}", flush=True)
        return 1


def main():
    col_status = run_collection_check()
    if col_status != 0:
        sys.exit(col_status)

    print("============================================================", flush=True)
    print("Stage 2: Vulnerable Implementation Evaluation", flush=True)
    print("============================================================", flush=True)
    vulnerable_status = run_test_target("vulnerable", expected_exit=1)

    print("============================================================", flush=True)
    print("Stage 3: Hardened Implementation Evaluation", flush=True)
    print("============================================================", flush=True)
    hardened_status = run_test_target("hardened", expected_exit=0)

    print("============================================================", flush=True)
    if vulnerable_status == 0 and hardened_status == 0:
        print("BENCHMARK COMPLETED SUCCESSFULLY: Skill 03 protections verified.", flush=True)
        print("Exit code: 0", flush=True)
        sys.exit(0)
    else:
        print("BENCHMARK FAILED.", flush=True)
        print("Exit code: 1", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
