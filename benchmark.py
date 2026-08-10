#!/usr/bin/env python3
"""Benchmark tool for K8s Health Monitor."""

import time
import json
from typing import Dict, List


class Benchmark:
    """Benchmark K8s monitoring operations."""

    def __init__(self):
        self.results = []

    def run(self, name: str, func, *args, **kwargs):
        """Run a benchmark and record results."""
        start = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start
            self.results.append({
                "name": name,
                "duration": duration,
                "status": "success"
            })
            return result
        except Exception as e:
            duration = time.time() - start
            self.results.append({
                "name": name,
                "duration": duration,
                "status": "error",
                "error": str(e)
            })
            return None

    def report(self) -> str:
        """Generate benchmark report."""
        lines = ["Benchmark Results", "=" * 40]
        for r in self.results:
            status = "✓" if r["status"] == "success" else "✗"
            lines.append(f"{status} {r['name']}: {r['duration']:.3f}s")
        return "\n".join(lines)

    def export_json(self, filename: str):
        """Export results to JSON."""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)