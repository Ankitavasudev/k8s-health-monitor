#!/usr/bin/env python3
"""Enhanced JSON export with pretty formatting."""

import json
from typing import Dict, Any
from datetime import datetime


def export_pretty(results: Dict[str, Any], filename: str):
    output = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "version": "3.0"
        },
        "results": results
    }
    with open(filename, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"Results exported to {filename}")