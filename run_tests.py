"""
Automated Test Suite Runner
===========================
Executes the full test suite in any environment (CI/CD, local, or reviewer sandbox).
Provides formatted test execution reporting and returns exit code 0 on all tests passing.

Usage:
  python run_tests.py
"""
import sys
import os
import subprocess

# Ensure project root is in sys.path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

def main():
    print("=" * 65)
    print("  Insider Threat Detection — Automated Test Suite Runner")
    print(f"  Root Directory: {ROOT_DIR}")
    print(f"  Python Version: {sys.version.split()[0]}")
    print("=" * 65)

    # 1. Check for pytest
    try:
        import pytest
        print("\n[Runner] Invoking pytest on tests/ ...\n")
        args = [
            "-v",
            os.path.join(ROOT_DIR, "tests"),
            "--disable-warnings",
            "-q"
        ]
        exit_code = pytest.main(args)
    except ImportError:
        print("\n[Runner] pytest not installed, falling back to unittest discovery...\n")
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover(start_dir=os.path.join(ROOT_DIR, "tests"), pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        exit_code = 0 if result.wasSuccessful() else 1

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("\n" + "=" * 65)
    if exit_code == 0:
        print("  [SUCCESS] ALL AUTOMATED TESTS EXECUTED AND PASSED!")
    else:
        print(f"  [FAILURE] TESTS FAILED (Exit code: {exit_code})")
    print("=" * 65 + "\n")

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
