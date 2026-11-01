"""Tests for k8s_monitor -- written against the module's real public API.

Everything here runs offline: the analyzers are pure functions over the
Kubernetes API objects that kubectl would return, so no cluster is needed.
"""

import pytest

from k8s_monitor import (
    Display,
    HealthAnalyzer,
    KubectlClient,
    PrometheusExporter,
    ResourceAnalyzer,
    SecurityScanner,
    _format_bytes,
    _get_age,
    generate_demo_data,
)


# --------------------------------------------------------------- kubectl client


def test_client_defaults():
    client = KubectlClient()
    assert client.kubeconfig is None
    assert client.context is None


def test_client_builds_command_without_flags():
    assert KubectlClient()._build_cmd(["get", "pods"]) == ["kubectl", "get", "pods"]


def test_client_builds_command_with_kubeconfig_and_context():
    cmd = KubectlClient(kubeconfig="/path", context="prod")._build_cmd(["get", "pods"])
    assert cmd == ["kubectl", "--kubeconfig", "/path", "--context", "prod", "get", "pods"]


def test_client_returns_empty_list_when_kubectl_is_missing(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("subprocess.run", boom)
    assert KubectlClient().get_pods() == []


def test_client_parses_json_items(monkeypatch):
    class Result:
        returncode = 0
        stdout = '{"items": [{"metadata": {"name": "web"}}]}'

    monkeypatch.setattr("subprocess.run", lambda *a, **k: Result())
    pods = KubectlClient().get_pods(namespace="default")
    assert pods == [{"metadata": {"name": "web"}}]


def test_client_survives_corrupt_json(monkeypatch):
    class Result:
        returncode = 0
        stdout = "not json"

    monkeypatch.setattr("subprocess.run", lambda *a, **k: Result())
    assert KubectlClient().get_nodes() == []


# ------------------------------------------------------------------- security


def make_pod(container=None, **spec_extra):
    spec = {"containers": [container or {"name": "app", "resources": {}}]}
    spec.update(spec_extra)
    return {"metadata": {"name": "pod", "namespace": "default"}, "spec": spec}


def test_privileged_container_is_critical():
    scanner = SecurityScanner()
    findings = scanner.scan_pods([make_pod({
        "name": "app",
        "resources": {},
        "securityContext": {"privileged": True},
    })])
    assert any(f["rule"] == "PrivilegedContainer" and f["severity"] == "CRITICAL" for f in findings)


def test_container_without_limits_is_medium():
    findings = SecurityScanner().scan_pods([make_pod()])
    assert any(f["rule"] == "NoResourceLimits" for f in findings)


def test_hardened_container_has_no_security_findings():
    container = {
        "name": "app",
        "resources": {"limits": {"cpu": "100m", "memory": "128Mi"}},
        "securityContext": {
            "runAsNonRoot": True,
            "readOnlyRootFilesystem": True,
            "privileged": False,
        },
    }
    pod = make_pod(container)
    pod["spec"]["securityContext"] = {"runAsNonRoot": True}
    assert SecurityScanner().scan_pods([pod]) == []


def test_all_capabilities_is_critical():
    findings = SecurityScanner().scan_pods([make_pod({
        "name": "app",
        "resources": {"limits": {"cpu": "1"}},
        "securityContext": {"capabilities": {"add": ["ALL"]}, "readOnlyRootFilesystem": True, "runAsNonRoot": True},
    })])
    assert any(f["rule"] == "AllCapabilities" for f in findings)


def test_host_network_is_flagged():
    findings = SecurityScanner().scan_pods([make_pod(hostNetwork=True)])
    assert any(f["rule"] == "HostNetwork" for f in findings)


def test_host_pid_is_flagged():
    findings = SecurityScanner().scan_pods([make_pod(hostPID=True)])
    assert any(f["rule"] == "HostPID" for f in findings)


def test_namespace_without_pod_security_is_medium():
    findings = SecurityScanner().scan_namespaces([
        {"metadata": {"name": "default", "labels": {}}},
    ])
    assert [f["severity"] for f in findings] == ["MEDIUM"]


def test_system_namespaces_are_skipped():
    findings = SecurityScanner().scan_namespaces([
        {"metadata": {"name": "kube-system", "labels": {}}},
        {"metadata": {"name": "kube-public", "labels": {}}},
        {"metadata": {"name": "kube-node-lease", "labels": {}}},
    ])
    assert findings == []


def test_loadbalancer_service_is_informational():
    findings = SecurityScanner().scan_services([
        {"metadata": {"name": "web", "namespace": "default"}, "spec": {"type": "LoadBalancer"}},
    ])
    assert [f["rule"] for f in findings] == ["LoadBalancerExposure"]


def test_summary_counts_every_severity():
    scanner = SecurityScanner()
    scanner.scan_pods([make_pod({"name": "a", "resources": {},
                                 "securityContext": {"privileged": True}})])
    summary = scanner.get_summary()
    assert summary["CRITICAL"] == 1
    assert set(summary) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ------------------------------------------------------------------ resources


@pytest.mark.parametrize("value,expected", [("250m", 0.25), ("2", 2.0), ("1000m", 1.0)])
def test_parse_cpu(value, expected):
    assert ResourceAnalyzer._parse_cpu(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("512Mi", 512 * 1024 ** 2),
    ("1Gi", 1024 ** 3),
    ("2048Ki", 2048 * 1024),
    ("1024", 1024.0),
])
def test_parse_memory(value, expected):
    assert ResourceAnalyzer._parse_memory(value) == expected


def test_node_capacity_is_summed():
    result = ResourceAnalyzer().analyze_nodes([
        {"status": {"allocatable": {"cpu": "4000m", "memory": "16Gi", "pods": "110"}}},
        {"status": {"allocatable": {"cpu": "8000m", "memory": "32Gi", "pods": "110"}}},
    ])
    assert result["total"] == 2
    assert result["cpu_capacity"] == 12.0
    assert result["memory_capacity"] == 48 * 1024 ** 3
    assert result["pods_capacity"] == 220


def test_pod_resources_split_bounded_and_unbounded():
    result = ResourceAnalyzer().analyze_pod_resources([
        {"spec": {"containers": [
            {"resources": {"requests": {"cpu": "100m", "memory": "128Mi"},
                           "limits": {"cpu": "200m", "memory": "256Mi"}}},
            {"resources": {}},
        ]}},
    ])
    assert result["total_containers"] == 2
    assert result["containers_with_limits"] == 1
    assert result["containers_with_requests"] == 1
    assert result["unbounded_containers"] == 1
    assert result["total_cpu_requests"] == 0.1
    assert result["total_mem_limits"] == 256 * 1024 ** 2


# --------------------------------------------------------------------- health


def test_nodes_health_counts_ready_conditions():
    result = HealthAnalyzer().analyze_nodes([
        {"status": {"conditions": [{"type": "Ready", "status": "True"}]}},
        {"status": {"conditions": [{"type": "Ready", "status": "False"}]}},
    ])
    assert (result["total"], result["ready"], result["not_ready"]) == (2, 1, 1)
    assert result["status"] == "WARNING"


def test_all_nodes_ready_is_healthy():
    result = HealthAnalyzer().analyze_nodes([
        {"status": {"conditions": [{"type": "Ready", "status": "True"}]}},
    ])
    assert result["status"] == "HEALTHY"


def test_pods_health_counts_phases_and_restart_loops():
    result = HealthAnalyzer().analyze_pods([
        {"status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]}},
        {"status": {"phase": "Running", "containerStatuses": [{"restartCount": 9}]}},
        {"status": {"phase": "Pending"}},
        {"status": {"phase": "Failed"}},
        {"status": {"phase": "Succeeded"}},
    ])
    assert result["total"] == 5
    assert result["running"] == 2
    assert result["restart_loops"] == 1
    assert result["unknown"] == 0
    assert result["status"] == "WARNING"


def test_deployments_replica_mismatch_is_degraded():
    result = HealthAnalyzer().analyze_deployments([
        {"status": {"replicas": 2, "readyReplicas": 2}},
        {"status": {"replicas": 2, "readyReplicas": 1}},
    ])
    assert (result["healthy"], result["degraded"]) == (1, 1)
    assert result["status"] == "WARNING"


def test_events_only_warnings_are_collected():
    result = HealthAnalyzer().analyze_events([
        {"type": "Warning", "reason": "BackOff", "message": "restarting",
         "involvedObject": {"namespace": "default", "name": "job"}},
        {"type": "Normal", "reason": "Scheduled", "message": "ok",
         "involvedObject": {"namespace": "default", "name": "pod"}},
    ])
    assert result["total"] == 2
    assert result["warnings"] == 1
    assert result["warning_details"][0]["reason"] == "BackOff"


# ----------------------------------------------------------------- prometheus


def test_prometheus_output_is_valid_exposition_format():
    exporter = PrometheusExporter()
    exporter.update_metrics(
        nodes=[{"status": {"conditions": [{"type": "Ready", "status": "True"}]}}],
        pods=[{"status": {"phase": "Running"}}, {"status": {"phase": "Pending"}}],
        services=[{}],
        deployments=[{"status": {"replicas": 1, "readyReplicas": 1}}],
        security_summary={"CRITICAL": 2},
        resource_analysis={"total_containers": 3, "unbounded_containers": 1},
    )
    output = exporter.generate_output()
    assert "cluster_nodes_total 1" in output
    assert "cluster_pods_pending 1" in output
    assert "cluster_security_critical 2" in output
    assert "cluster_containers_unbounded 1" in output
    assert output.count("# TYPE") == output.count("# HELP")


# -------------------------------------------------------------------- helpers


def test_format_bytes_switches_units():
    assert _format_bytes(512) == "512.0 B"
    assert _format_bytes(2048) == "2.0 KB"
    assert _format_bytes(5 * 1024 ** 3) == "5.0 GB"


def test_get_age_handles_garbage():
    assert _get_age("not-a-date") == "unknown"
    assert _get_age("") == "unknown"


# ------------------------------------------------------------------ demo data


def test_demo_data_has_the_expected_shape():
    nodes, pods, services, deployments, events, namespaces = generate_demo_data()
    assert len(nodes) == 4
    assert pods and services and deployments and events and namespaces
    # The demo deliberately contains one unhealthy node and one pending pod so
    # the dashboard exercises its warning paths.
    assert any(n["status"]["conditions"][0]["status"] == "False" for n in nodes)
    assert any(p["status"]["phase"] == "Pending" for p in pods)


def test_demo_data_passes_through_every_analyzer():
    nodes, pods, services, deployments, events, namespaces = generate_demo_data()
    scanner = SecurityScanner()
    scanner.scan_pods(pods)
    scanner.scan_deployments(deployments)
    scanner.scan_services(services)
    scanner.scan_namespaces(namespaces)

    assert HealthAnalyzer().analyze_nodes(nodes)["not_ready"] == 1
    assert HealthAnalyzer().analyze_pods(pods)["pending"] == 1
    assert ResourceAnalyzer().analyze_pod_resources(pods)["total_containers"] >= 5
    assert scanner.get_summary()["CRITICAL"] >= 1


def test_display_status_badges_render():
    assert "HEALTHY" in Display.status_badge("HEALTHY")
    assert "CRITICAL" in Display.status_badge("CRITICAL")


# ------------------------------------------------------- missing data honesty


def test_empty_cluster_reports_unknown_not_healthy():
    """A failed kubectl call returns [] -- that must not look like a healthy cluster."""
    analyzer = HealthAnalyzer()
    assert analyzer.analyze_nodes([])["status"] == "UNKNOWN"
    assert analyzer.analyze_pods([])["status"] == "UNKNOWN"
    assert analyzer.analyze_deployments([])["status"] == "UNKNOWN"
    assert analyzer.analyze_services([])["status"] == "UNKNOWN"


def test_unknown_badge_is_not_green():
    assert "UNKNOWN" in Display.status_badge("UNKNOWN")


# ------------------------------------------------------------------- CLI output


def test_json_output_is_pure_json():
    """`--output json` is meant to be piped into jq, so no tables may leak in."""
    import json
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, str(repo / "k8s_monitor.py"), "--demo", "--output", "json"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["pods"]["total"] > 0
    assert payload["nodes"]["status"] in {"HEALTHY", "WARNING", "CRITICAL"}


def test_prometheus_output_is_pure_exposition_text():
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, str(repo / "k8s_monitor.py"), "--demo", "--output", "prometheus"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("# HELP cluster_")
    assert "cluster_nodes_total" in result.stdout
