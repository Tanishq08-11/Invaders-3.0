"""
Pytest root configuration
Ensures the project root is always in sys.path regardless of the current working directory,
and sets up standard fixtures for review environments.
"""
import os
import sys

# Ensure root directory is always on python path
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# The pipeline/route suites call SOC endpoints without a portal session; auth is
# covered separately in tests/test_auth_and_files.py, which re-enables the guard.
os.environ.setdefault("SOC_AUTH_REQUIRED", "false")
