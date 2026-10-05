"""
conftest.py — makes the src/ modules importable from the tests.

With the src/ layout the honeypot modules live one directory up in ../src,
so we add that to sys.path before any test imports them. This mirrors how
the services run in production: each systemd unit sets WorkingDirectory to
the install dir and the modules import each other flatly.
"""
import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
