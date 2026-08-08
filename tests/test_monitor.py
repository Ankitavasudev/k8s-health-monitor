import pytest
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8s_monitor import (
    HealthAnalyzer, HealthStatus, KubectlClient, Display, Exporter,
    ClusterReport, _get_age, generate_demo_data
)


class TestHealthAnalyzer:
    def setup_method(self):
        self.analyzer = HealthAnalyzer()

    def test_analyze_nodes_all_ready(self):
        nodes = [
            {"metadata": {"name": "node-1", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
            {"metadata": {"name": "node-2", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
        ]
        result = self.analyzer.analyze_nodes(nodes)
        assert result["total"] == 2
        assert result["ready"] == 2
        assert result["not_ready"] == 0
        assert result["status"] == "HEALTHY"
        assert result["score"] == 100.0

    def test_analyze_nodes_one_not_ready(self):
        nodes = [
            {"metadata": {"name": "node-1", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
            {"metadata": {"name": "node-2", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "False"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
        ]
        result = self.analyzer.analyze_nodes(nodes)
        assert result["ready"] == 1
        assert result["not_ready"] == 1
        assert result["status"] == "WARNING"
        assert result["score"] == 50.0

    def test_analyze_nodes_multiple_not_ready(self):
        nodes = [
            {"metadata": {"name": "node-1", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "False"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
            {"metadata": {"name": "node-2", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "False"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
            {"metadata": {"name": "node-3", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
        ]
        result = self.analyzer.analyze_nodes(nodes)
        assert result["not_ready"] == 2
        assert result["status"] == "CRITICAL"

    def test_analyze_nodes_empty(self):
        result = self.analyzer.analyze_nodes([])
        assert result["total"] == 0
        assert result["score"] == 0

    def test_analyze_nodes_versions(self):
        nodes = [
            {"metadata": {"name": "node-1", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
            {"metadata": {"name": "node-2", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.31.1"}}},
        ]
        result = self.analyzer.analyze_nodes(nodes)
        assert len(result["versions"]) == 2
        assert "v1.30.0" in result["versions"]
        assert "v1.31.1" in result["versions"]

    def test_analyze_pods_all_running(self):
        pods = [
            {"metadata": {"name": "pod-1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]}},
            {"metadata": {"name": "pod-2", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Running", "containerStatuses": [{"restartCount": 2}]}},
        ]
        result = self.analyzer.analyze_pods(pods)
        assert result["total"] == 2
        assert result["running"] == 2
        assert result["failed"] == 0
        assert result["status"] == "HEALTHY"
        assert result["score"] == 100.0

    def test_analyze_pods_with_failed(self):
        pods = [
            {"metadata": {"name": "pod-1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Running", "containerStatuses": []}},
            {"metadata": {"name": "pod-2", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Failed", "containerStatuses": []}},
        ]
        result = self.analyzer.analyze_pods(pods)
        assert result["failed"] == 1
        assert "default/pod-2" in result["failed_pods"]

    def test_analyze_pods_with_pending(self):
        pods = [
            {"metadata": {"name": "pod-1", "namespace": "kube-system", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Pending", "containerStatuses": []}},
        ]
        result = self.analyzer.analyze_pods(pods)
        assert result["pending"] == 1
        assert "kube-system/pod-1" in result["pending_pods"]

    def test_analyze_pods_restart_loop(self):
        pods = [
            {"metadata": {"name": "pod-1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Running", "containerStatuses": [{"restartCount": 10}]}},
        ]
        result = self.analyzer.analyze_pods(pods)
        assert result["restart_loops"] == 1

    def test_analyze_services(self):
        services = [
            {"metadata": {"name": "svc-1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "spec": {"type": "ClusterIP", "clusterIP": "10.0.0.1", "ports": [{"port": 80, "protocol": "TCP"}]}},
            {"metadata": {"name": "svc-2", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "spec": {"type": "LoadBalancer", "clusterIP": "10.0.0.2", "ports": [{"port": 443, "protocol": "TCP"}]}},
        ]
        result = self.analyzer.analyze_services(services)
        assert result["total"] == 2
        assert result["types"]["ClusterIP"] == 1
        assert result["types"]["LoadBalancer"] == 1

    def test_analyze_deployments_healthy(self):
        deployments = [
            {"metadata": {"name": "dep-1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"replicas": 3, "readyReplicas": 3, "updatedReplicas": 3, "availableReplicas": 3}},
        ]
        result = self.analyzer.analyze_deployments(deployments)
        assert result["total"] == 1
        assert result["healthy"] == 1
        assert result["degraded"] == 0

    def test_analyze_deployments_degraded(self):
        deployments = [
            {"metadata": {"name": "dep-1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"replicas": 3, "readyReplicas": 1, "updatedReplicas": 3, "availableReplicas": 1}},
        ]
        result = self.analyzer.analyze_deployments(deployments)
        assert result["degraded"] == 1
        assert "default/dep-1 (1/3)" in result["degraded_deployments"]

    def test_analyze_events_no_warnings(self):
        events = [
            {"metadata": {"namespace": "default"}, "type": "Normal", "reason": "Started",
             "message": "Container started", "involvedObject": {"name": "pod-1"}},
        ]
        result = self.analyzer.analyze_events(events)
        assert result["warnings"] == 0
        assert result["status"] == "HEALTHY"

    def test_analyze_events_with_warnings(self):
        events = [
            {"metadata": {"namespace": "default"}, "type": "Warning", "reason": "BackOff",
             "message": "Back-off restarting", "involvedObject": {"name": "pod-1"}},
            {"metadata": {"namespace": "default"}, "type": "Warning", "reason": "Unhealthy",
             "message": "Readiness probe failed", "involvedObject": {"name": "pod-2"}},
        ]
        result = self.analyzer.analyze_events(events)
        assert result["warnings"] == 2
        assert len(result["warning_events"]) == 2


class TestGetAge:
    def test_days(self):
        ts = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        assert _get_age(ts) == "5d"

    def test_hours(self):
        ts = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        assert _get_age(ts) == "3h"

    def test_months(self):
        ts = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        assert _get_age(ts) == "2mo"

    def test_years(self):
        ts = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        assert _get_age(ts) == "1y"

    def test_empty(self):
        assert _get_age("") == "unknown"

    def test_invalid(self):
        assert _get_age("not-a-date") == "unknown"


class TestDemoData:
    def test_generate_demo_data(self):
        nodes, pods, services, deployments, events = generate_demo_data()
        assert len(nodes) == 4
        assert len(pods) == 10
        assert len(services) == 4
        assert len(deployments) == 5
        assert len(events) == 3

    def test_demo_nodes_have_roles(self):
        nodes, _, _, _, _ = generate_demo_data()
        for node in nodes:
            assert "labels" in node["metadata"]


class TestExporter:
    def test_to_json(self, tmp_path):
        report = ClusterReport(
            timestamp="2026-08-06T12:00:00",
            node_analysis={"total": 2, "ready": 2, "status": "HEALTHY", "score": 100},
            pod_analysis={"total": 5, "running": 5, "failed": 0, "status": "HEALTHY", "score": 100},
            service_analysis={"total": 3, "status": "HEALTHY", "score": 100},
            deployment_analysis={"total": 2, "healthy": 2, "status": "HEALTHY", "score": 100},
            event_analysis={"total": 10, "warnings": 0, "status": "HEALTHY", "score": 100},
            overall_status="HEALTHY",
            nodes=[], pods=[], services=[], deployments=[]
        )
        filepath = str(tmp_path / "report.json")
        Exporter.to_json(report, filepath)
        with open(filepath) as f:
            data = json.load(f)
        assert data["overall_status"] == "HEALTHY"
        assert data["node_analysis"]["total"] == 2

    def test_to_text(self, tmp_path):
        report = ClusterReport(
            timestamp="2026-08-06T12:00:00",
            node_analysis={"total": 2, "ready": 2, "not_ready": 0},
            pod_analysis={"total": 5, "running": 5, "failed": 0, "pending": 0, "restart_loops": 0},
            service_analysis={"total": 3},
            deployment_analysis={"total": 2, "healthy": 2, "degraded": 0},
            event_analysis={"warnings": 0},
            overall_status="HEALTHY",
            nodes=[], pods=[], services=[], deployments=[]
        )
        filepath = str(tmp_path / "report.txt")
        Exporter.to_text(report, filepath)
        with open(filepath) as f:
            content = f.read()
        assert "HEALTHY" in content
        assert "Nodes:" in content


class TestDisplay:
    def test_status_badge(self):
        assert "HEALTHY" in Display.status_badge("HEALTHY")
        assert "WARNING" in Display.status_badge("WARNING")
        assert "CRITICAL" in Display.status_badge("CRITICAL")

    def test_score_bar(self):
        bar = Display.score_bar(80.0)
        assert "80%" in bar
        bar_low = Display.score_bar(30.0)
        assert "30%" in bar_low
