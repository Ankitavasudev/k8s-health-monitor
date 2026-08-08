import pytest
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from k8s_monitor import (
    HealthAnalyzer, SecurityScanner, ResourceAnalyzer, KubectlClient,
    PVCInfo, ResourceQuota, NetworkPolicy, SecurityIssue,
    Recommender, Display, generate_demo_data
)


class TestHealthAnalyzer:
    def test_nodes_all_ready(self):
        nodes = [
            {"metadata": {"name": "n1", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
            {"metadata": {"name": "n2", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
        ]
        result = HealthAnalyzer.nodes(nodes)
        assert result["total"] == 2
        assert result["ready"] == 2
        assert result["score"] == 100.0

    def test_nodes_one_not_ready(self):
        nodes = [
            {"metadata": {"name": "n1", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
            {"metadata": {"name": "n2", "labels": {}, "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"conditions": [{"type": "Ready", "status": "False"}], "nodeInfo": {"kubeletVersion": "v1.30.0"}}},
        ]
        result = HealthAnalyzer.nodes(nodes)
        assert result["not_ready"] == 1
        assert result["score"] == 50.0

    def test_nodes_empty(self):
        result = HealthAnalyzer.nodes([])
        assert result["total"] == 0
        assert result["score"] == 0

    def test_pods_all_running(self):
        pods = [
            {"metadata": {"name": "p1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]},
             "spec": {"nodeName": "n1", "containers": [{"name": "c1", "securityContext": {}}]}},
        ]
        result = HealthAnalyzer.pods(pods)
        assert result["running"] == 1
        assert result["failed"] == 0

    def test_pods_with_failed(self):
        pods = [
            {"metadata": {"name": "p1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Failed", "containerStatuses": []},
             "spec": {"nodeName": "n1", "containers": []}},
        ]
        result = HealthAnalyzer.pods(pods)
        assert result["failed"] == 1

    def test_pods_restart_loop(self):
        pods = [
            {"metadata": {"name": "p1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"phase": "Running", "containerStatuses": [{"restartCount": 10}]},
             "spec": {"nodeName": "n1", "containers": [{"name": "c1", "securityContext": {}}]}},
        ]
        result = HealthAnalyzer.pods(pods)
        assert result["restart_loops"] == 1

    def test_deployments_healthy(self):
        deps = [
            {"metadata": {"name": "d1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"replicas": 3, "readyReplicas": 3}},
        ]
        result = HealthAnalyzer.deployments(deps)
        assert result["healthy"] == 1
        assert result["degraded"] == 0

    def test_deployments_degraded(self):
        deps = [
            {"metadata": {"name": "d1", "namespace": "default", "creationTimestamp": "2026-01-01T00:00:00Z"},
             "status": {"replicas": 3, "readyReplicas": 1}},
        ]
        result = HealthAnalyzer.deployments(deps)
        assert result["degraded"] == 1


class TestSecurityScanner:
    def test_detects_privileged(self):
        client = MagicMock()
        client.get_pods.return_value = [
            {"metadata": {"name": "pod1", "namespace": "default"},
             "status": {"phase": "Running", "containerStatuses": []},
             "spec": {"containers": [{"name": "c1", "securityContext": {"privileged": True}}]}}
        ]
        client.get_clusterroles.return_value = []
        client.get_service_accounts.return_value = []
        client.get_netpol.return_value = []
        client.get_namespaces.return_value = []

        scanner = SecurityScanner(client)
        issues = scanner.scan()
        privileged = [i for i in issues if i.rule == "SEC001"]
        assert len(privileged) == 1

    def test_detects_root_user(self):
        client = MagicMock()
        client.get_pods.return_value = [
            {"metadata": {"name": "pod1", "namespace": "default"},
             "status": {"phase": "Running", "containerStatuses": []},
             "spec": {"containers": [{"name": "c1", "securityContext": {"runAsUser": 0}}]}}
        ]
        client.get_clusterroles.return_value = []
        client.get_service_accounts.return_value = []
        client.get_netpol.return_value = []
        client.get_namespaces.return_value = []

        scanner = SecurityScanner(client)
        issues = scanner.scan()
        root = [i for i in issues if i.rule == "SEC002"]
        assert len(root) == 1

    def test_rbac_wildcard(self):
        client = MagicMock()
        client.get_pods.return_value = []
        client.get_clusterroles.return_value = [
            {"metadata": {"name": "admin"}, "rules": [{"resources": ["*"], "verbs": ["*"]}]}
        ]
        client.get_service_accounts.return_value = []
        client.get_netpol.return_value = []
        client.get_namespaces.return_value = []

        scanner = SecurityScanner(client)
        issues = scanner.scan()
        rbac = [i for i in issues if i.rule == "RBAC001"]
        assert len(rbac) == 1

    def test_network_policy_missing(self):
        client = MagicMock()
        client.get_pods.return_value = []
        client.get_clusterroles.return_value = []
        client.get_service_accounts.return_value = []
        client.get_netpol.return_value = []
        client.get_namespaces.return_value = [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "production"}},
        ]

        scanner = SecurityScanner(client)
        issues = scanner.scan()
        net = [i for i in issues if i.rule == "NET001"]
        assert len(net) == 2


class TestRecommender:
    def test_critical_recommendations(self):
        issues = [SecurityIssue("pod1", "default", "CRITICAL", "SEC001", "privileged", "fix")]
        recs = Recommender().generate(issues, [], [], {"not_ready": 0}, {"restart_loops": 0})
        assert any("CRITICAL" in r for r in recs)

    def test_unbound_pvc_recommendation(self):
        pvcs = [PVCInfo("pvc1", "default", "Pending", "N/A", "standard", False)]
        recs = Recommender().generate([], [], pvcs, {"not_ready": 0}, {"restart_loops": 0})
        assert any("unbound" in r.lower() for r in recs)

    def test_healthy_cluster(self):
        recs = Recommender().generate([], [], [], {"not_ready": 0}, {"restart_loops": 0})
        assert any("healthy" in r.lower() for r in recs)


class TestDemoData:
    def test_generates_valid_data(self):
        nodes, pods, deps = generate_demo_data()
        assert len(nodes) > 0
        assert len(pods) > 0
        assert len(deps) > 0


class TestDisplay:
    def test_bar(self):
        bar = Display.bar(80.0)
        assert "80%" in bar
        bar_low = Display.bar(30.0)
        assert "30%" in bar_low