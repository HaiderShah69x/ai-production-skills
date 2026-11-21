#!/usr/bin/env python3
"""
attacks/run_skill02_benchmark.py — Automated AST Mutation Verification Runner.

Stages:
  Stage 1: Collection Guard Check (asserts >= 4 security tests collected)
  Stage 2: Dynamic AST Mutation Engine
           - Parses clean banking code to AST
           - Generates >= 6 distinct syntactically valid mutants
           - Runs pytest against each mutant in an isolated temp module
           - Calculates Mutation Score = (killed / total) * 100 (Threshold >= 90%)
  Stage 3: Clean Implementation Verification
           - Runs pytest against clean banking service (Must PASS 100%, exit 0)
"""

import os
import subprocess
import sys
import tempfile
import pathlib
from typing import Tuple

REPO_ROOT = pathlib.Path(__file__).parent.parent
TEST_FILE = REPO_ROOT / "tests" / "test_harness_adversarial.py"
SOURCE_FILE = REPO_ROOT / "fixtures" / "banking_fixtures.py"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from fixtures.ast_mutator import generate_mutants

MIN_REQUIRED_TESTS = 4
REQUIRED_MUTATION_SCORE = 90.0  # percentage


def run_collection_check() -> int:
    """Run pytest --collect-only to verify collection guard."""
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

    print("  [PASS] Collection guard passed: all required security tests registered.\n", flush=True)
    return 0


def run_ast_mutation_engine() -> Tuple[int, float]:
    """Dynamically generate AST mutants and execute tests against each."""
    print("============================================================", flush=True)
    print("Stage 2: Dynamic AST Mutation Engine", flush=True)
    print("============================================================", flush=True)

    source_code = SOURCE_FILE.read_text(encoding="utf-8")
    mutants = generate_mutants(source_code)
    total_mutants = len(mutants)

    print(f"  Generated {total_mutants} AST mutants from {SOURCE_FILE.name}", flush=True)
    if total_mutants < 6:
        print(f"  [FAIL] Mutation engine produced {total_mutants} mutants; expected at least 6.", flush=True)
        return (1, 0.0)

    killed_mutants = 0

    for idx, (mutant_name, mutated_code) in enumerate(mutants, 1):
        fd, temp_path_str = tempfile.mkstemp(suffix=".py", prefix=f"mutant_{idx}_")
        temp_path = pathlib.Path(temp_path_str)
        try:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(mutated_code)

            env = os.environ.copy()
            env["MUTANT_MODULE_PATH"] = str(temp_path)

            cmd = [sys.executable, "-m", "pytest", str(TEST_FILE), "-q"]
            proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)

            # Mutant is killed if pytest fails (exit code != 0)
            if proc.returncode != 0:
                killed_mutants += 1
                summary = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "failed"
                print(f"  [{idx:02d}/{total_mutants:02d}] KILLED:   {mutant_name} ({summary})", flush=True)
            else:
                print(f"  [{idx:02d}/{total_mutants:02d}] SURVIVED: {mutant_name} (tests passed unexpectedly!)", flush=True)
        finally:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

    mutation_score = (killed_mutants / total_mutants) * 100.0
    print(f"\n  Mutation Score: {mutation_score:.1f}% ({killed_mutants}/{total_mutants} killed)", flush=True)
    print(f"  Required Score: >= {REQUIRED_MUTATION_SCORE}%", flush=True)

    if mutation_score >= REQUIRED_MUTATION_SCORE:
        print(f"  [PASS] AST Mutation threshold satisfied: {mutation_score:.1f}% >= {REQUIRED_MUTATION_SCORE}%\n", flush=True)
        return (0, mutation_score)
    else:
        print(f"  [FAIL] Mutation score below threshold: {mutation_score:.1f}% < {REQUIRED_MUTATION_SCORE}%\n", flush=True)
        return (1, mutation_score)


def run_clean_verification() -> int:
    """Run pytest against clean un-mutated implementation."""
    print("============================================================", flush=True)
    print("Stage 3: Clean Implementation Verification", flush=True)
    print("============================================================", flush=True)

    env = os.environ.copy()
    env.pop("MUTANT_MODULE_PATH", None)

    cmd = [sys.executable, "-m", "pytest", str(TEST_FILE), "-q"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)

    if proc.returncode == 0:
        summary = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "passed"
        print(f"  [PASS] Clean banking implementation passed 100%: {summary}\n", flush=True)
        return 0
    else:
        print(f"  [FAIL] Clean implementation failed verification tests!\n", flush=True)
        return 1


def main():
    col_status = run_collection_check()
    if col_status != 0:
        sys.exit(col_status)

    matrix_status, score = run_ast_mutation_engine()
    clean_status = run_clean_verification()

    print("============================================================", flush=True)
    if matrix_status == 0 and clean_status == 0:
        print("ALL TESTS PASSED: AST Mutation engine verified. Kill rate >= 90%.", flush=True)
        print("Exit code: 0", flush=True)
        sys.exit(0)
    else:
        print("BENCHMARK FAILED: Mutation kill score below threshold or clean suite failed.", flush=True)
        print("Exit code: 1", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
