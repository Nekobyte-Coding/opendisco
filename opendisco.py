#!/usr/bin/env python3
"""Command-line launcher: ./opendisco.py [options]. The scanner lives in src/opendisco."""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

if __name__ == "__main__":
    from opendisco import core

    # Your own networks file: kept out of git, made from the default the first time.
    mine = os.path.join(HERE, "networks.txt")
    if not os.path.exists(mine):
        shutil.copyfile(core.DEFAULT_NETWORKS_FILE, mine)
    core.DEFAULT_NETWORKS_FILE = mine
    sys.exit(core.main())
