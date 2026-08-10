#!/usr/bin/env python3
"""Quick summary output for K8s Health Monitor."""

import json
from typing import Dict, Any


def print_summary(results: Dict[str, Any]):
    """Print a concise one-line summary of cluster health."""
    security = results.get("security_issues", [])
    health = results.get("health_analysis", {})
    resources = results.get("resource_analysis", [])
    recs = results.get("recommendations", [])

    critical = sum(1 for i in security if i.get("severity") == "CRITICAL")
    warning = sum(1 for i in security if i.get("severity") == "WARNING")

    total_pods = health.get("total", 0)
    running = health.get("running", 0)
    failed = health.get("failed", 0)

    total_nodes = len(resources)
    ready_nodes = sum(1 for r in resources if r.get("status") == "Ready")

    status = "HEALTHY" if failed == 0 and critical == 0 else "DEGRADED"
    if failed > 0 or critical > 0:
        status = "CRITICAL"

    print(f"Cluster Status: {status}")
    print(f"Nodes: {ready_nodes}/{total_nodes} ready | Pods: {running}/{total_pods} running | Failed: {failed}")
    print(f"Security: {critical} critical, {warning} warning | Recommendations: {len(recs)}")

    if critical > 0:
        print("\nCritical Issues:")
        for issue in security:
            if issue.get("severity") == "CRITICAL":
                print(f"  - [{issue.get('rule')}] {issue.get('message')}")

    return status
