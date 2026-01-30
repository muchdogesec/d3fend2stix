#!/usr/bin/env python3
"""
d3fend2stix - Convert D3FEND knowledge graph to STIX 2.1 objects

Usage:
    python3 run_d3fend2stix.py
"""
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from d3fend2stix.main import main

if __name__ == "__main__":
    sys.exit(main())
