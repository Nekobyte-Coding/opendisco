#!/usr/bin/env python3
"""Command-line launcher: ./opendisco.py [options]. The scanner lives in src/opendisco."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

if __name__ == "__main__":
    from opendisco import core

    core.DEFAULT_NETWORKS_FILE = os.path.join(HERE, "networks.txt")
    sys.exit(core.main())
