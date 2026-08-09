#!/usr/bin/env python3
"""Prometheus metrics exporter for K8s Health Monitor."""

import json
from typing import Dict, List, Any


class PrometheusExporter:
    """Export K8s health metrics in Prometheus format."""

    def __init__(self):
        self.metrics = []

    def _add_metric(self, name: str, metric_type: str, value: Any, labels: Dict[str, str] = None):
        """Add a metric to the exporter."""
        label_str = ""
        if labels:
            label_pairs = [f'{k}="{v}"' for k, v in labels.items()]
            label_str = "{" + ",".join(label_pairs) + "}"
        self.metrics.append(f"# TYPE {name} {metric_type}")
        self.metrics.append(f"{name}{label_str} {value}")

    def export_health_results(self, results: Dict[str, Any]):
        """Export health check results as Prometheus metrics."""
        # Security issues
        security_issues = results.get("security_issues", [])
        critical = sum(1 for i in security_issues if i.get("severity") == "CRITICAL")
        warning = sum(1 for i in security_issues if i.get("severity") == "WARNING")
        self._add_metric("k8s_security_issues_critical", "gauge", critical)
        self._add_metric("k8s_security_issues_warning", "gauge", warning)
        self._add_metric("k8s_security_issues_total", "gauge", len(security_issues))

        # Health analysis
        health = results.get("health_analysis", {})
        self._add_metric("k8s_pods_total", "gauge", health.get("total", 0))
        self._add_metric("k8s_pods_running", "gauge", health.get("running", 0))
        self._add_metric("k8s_pods_pending", "gauge", health.get("pending", 0))
        self._add_metric("k8s_pods_failed", "gauge", health.get("failed", 0))

        # Resource analysis
        resources = results.get("resource_analysis", [])
        ready = sum(1 for r in resources if r.get("status") == "Ready")
        not_ready = sum(1 for r in resources if r.get("status") == "NotReady")
        self._add_metric("k8s_nodes_ready", "gauge", ready)
        self._add_metric("k8s_nodes_not_ready", "gauge", not_ready)

        # Recommendations
        recommendations = results.get("recommendations", [])
        self._add_metric("k8s_recommendations_total", "gauge", len(recommendations))

    def render(self) -> str:
        """Render metrics in Prometheus exposition format."""
        return "\n".join(self.metrics) + "\n"


def export_to_file(results: Dict[str, Any], filename: str):
    """Export metrics to a file."""
    exporter = PrometheusExporter()
    exporter.export_health_results(results)
    with open(filename, "w") as f:
        f.write(exporter.render())


def export_to_string(results: Dict[str, Any]) -> str:
    """Export metrics as a string."""
    exporter = PrometheusExporter()
    exporter.export_health_results(results)
    return exporter.render()