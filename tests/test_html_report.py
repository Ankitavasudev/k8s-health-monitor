"""Tests for the standalone HTML report renderer."""

import re

from html_report import render_html


def sample_report(**overrides):
    report = {
        "timestamp": "2026-11-01T12:00:00",
        "nodes": {"total": 3, "ready": 2, "not_ready": 1, "status": "WARNING"},
        "pods": {
            "total": 4, "running": 3, "pending": 1, "failed": 0,
            "succeeded": 0, "unknown": 0, "restart_loops": 1, "status": "WARNING",
        },
        "services": {"total": 2, "status": "HEALTHY"},
        "deployments": {"total": 2, "healthy": 1, "degraded": 1, "status": "WARNING"},
        "resources": {
            "total_containers": 8, "containers_with_limits": 6,
            "containers_with_requests": 7, "unbounded_containers": 1,
            "total_cpu_requests": 1.5, "total_cpu_limits": 3.0,
            "total_mem_requests": 512 * 1024 ** 2, "total_mem_limits": 1024 ** 3,
        },
        "node_resources": {
            "total": 3, "cpu_capacity": 12, "memory_capacity": 32 * 1024 ** 3,
            "pods_capacity": 330,
        },
        "events": {
            "total": 5, "warnings": 1,
            "warning_details": [
                {"reason": "BackOff", "message": "back-off restarting", "object": "shop/api-1"},
            ],
        },
        "security": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 0},
        "findings": [
            {"resource": "shop/api-1", "container": "api", "severity": "MEDIUM",
             "rule": "NoResourceLimits", "message": "No resource limits defined"},
            {"resource": "shop/api-1", "container": "api", "severity": "CRITICAL",
             "rule": "PrivilegedContainer", "message": "Container runs in privileged mode"},
        ],
        "pod_details": [
            {"namespace": "shop", "name": "api-1", "phase": "Running", "restarts": 0},
        ],
    }
    report.update(overrides)
    return report


def test_document_is_well_formed_and_declares_utf8():
    html = render_html(sample_report())
    assert html.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in html
    assert '<meta charset="utf-8">' in html
    assert html.rstrip().endswith("</html>")


def test_report_is_self_contained():
    """No scripts, no remote styles, no images: the file must work offline."""
    html = render_html(sample_report())
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "src=" not in html.lower()
    links = re.findall(r'href="([^"]+)"', html)
    assert links == ["https://github.com/Ankitavasudev/k8s-health-monitor"]


def test_counts_and_statuses_are_rendered():
    html = render_html(sample_report(), mode="sample data", context="prod")
    assert "3 of 3" not in html
    assert "2 of 3 ready" in html
    assert "1 degraded of 2" in html
    assert "source: sample data" in html
    assert "context: prod" in html
    assert ">WARNING<" in html
    assert ">HEALTHY<" in html


def test_severity_badges_are_ordered_worst_first():
    html = render_html(sample_report())
    table = html.split("Findings, worst first")[1]
    critical = table.index("PrivilegedContainer")
    medium = table.index("NoResourceLimits")
    assert critical < medium


def test_hostile_resource_names_are_escaped():
    hostile = '<script>alert("x")</script>'
    report = sample_report()
    report["findings"][0]["resource"] = hostile
    report["pod_details"][0]["name"] = hostile
    html = render_html(report)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_unreachable_cluster_reports_unknown_not_healthy():
    report = sample_report(
        nodes={"total": 0, "ready": 0, "not_ready": 0, "status": "UNKNOWN"},
        pods={"total": 0, "running": 0, "pending": 0, "failed": 0,
              "succeeded": 0, "unknown": 0, "restart_loops": 0, "status": "UNKNOWN"},
        services={"total": 0, "status": "UNKNOWN"},
        deployments={"total": 0, "healthy": 0, "degraded": 0, "status": "UNKNOWN"},
    )
    html = render_html(report)
    assert ">UNKNOWN<" in html
    assert ">HEALTHY<" not in html


def test_empty_sections_do_not_crash():
    html = render_html({"timestamp": "2026-11-01T12:00:00"})
    assert "<!DOCTYPE html>" in html
    assert "No pods returned." in html
    assert "No warning events." in html
