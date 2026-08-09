#!/usr/bin/env python3
"""JSON export utilities for K8s Health Monitor."""

import json
from datetime import datetime
from typing import Dict, List, Any


class HealthReportEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


def export_health_report(results: Dict[str, Any], filename: str):
    report = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "version": "3.0.0",
            "tool": "K8s Health Monitor"
        },
        "summary": {
            "total_pods": results.get("total_pods", 0),
            "healthy_pods": results.get("healthy_pods", 0),
            "unhealthy_pods": results.get("unhealthy_pods", 0),
            "security_issues": len(results.get("security_issues", [])),
            "resource_issues": len(results.get("resource_issues", []))
        },
        "details": results
    }

    with open(filename, "w") as f:
        json.dump(report, f, cls=HealthReportEncoder, indent=2)

    print(f"Report exported to {filename}")


def export_security_report(findings: List[Dict], filename: str):
    report = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "scanner": "K8s Security Scanner"
        },
        "summary": {
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"])
        },
        "findings": findings
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Security report exported to {filename}")


def export_namespace_report(namespaces: List[Dict], filename: str):
    report = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "total_namespaces": len(namespaces)
        },
        "namespaces": namespaces
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Namespace report exported to {filename}")


def pretty_print_json(data: Dict[str, Any]):
    print(json.dumps(data, indent=2, cls=HealthReportEncoder))