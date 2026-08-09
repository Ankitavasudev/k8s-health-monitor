import pytest
from k8s_monitor import K8sMonitor, SecurityScanner, ResourceAnalyzer, HealthAnalyzer, Recommender


def test_k8s_monitor_init():
    monitor = K8sMonitor()
    assert monitor is not None


def test_k8s_monitor_init_with_config():
    monitor = K8sMonitor(kubeconfig="/path/to/config")
    assert monitor is not None


def test_security_scanner_init():
    from k8s_monitor import KubectlClient
    client = KubectlClient()
    scanner = SecurityScanner(client)
    assert scanner is not None


def test_resource_analyzer_init():
    from k8s_monitor import KubectlClient
    client = KubectlClient()
    analyzer = ResourceAnalyzer(client)
    assert analyzer is not None


def test_health_analyzer_init():
    from k8s_monitor import KubectlClient
    client = KubectlClient()
    analyzer = HealthAnalyzer(client)
    assert analyzer is not None


def test_recommender_init():
    recommender = Recommender([], [], {})
    assert recommender is not None


def test_recommender_get_recommendations():
    recommender = Recommender([], [], {"failed": 0})
    recs = recommender.get_recommendations()
    assert isinstance(recs, list)


def test_recommender_with_issues():
    from k8s_monitor import SecurityIssue
    issues = [
        SecurityIssue(
            resource="test",
            namespace="default",
            severity="CRITICAL",
            rule="SEC001",
            message="Test issue",
            remediation="Fix it"
        )
    ]
    recommender = Recommender(issues, [], {"failed": 0})
    recs = recommender.get_recommendations()
    assert len(recs) > 0


def test_kubectl_client_init():
    from k8s_monitor import KubectlClient
    client = KubectlClient()
    assert client.kubeconfig is None
    assert client.context is None
    assert client.namespace == ""


def test_kubectl_client_with_config():
    from k8s_monitor import KubectlClient
    client = KubectlClient(kubeconfig="/path", context="my-context", namespace="prod")
    assert client.kubeconfig == "/path"
    assert client.context == "my-context"
    assert client.namespace == "prod"


def test_kubectl_client_cmd():
    from k8s_monitor import KubectlClient
    client = KubectlClient(kubeconfig="/path", context="ctx", namespace="ns")
    cmd = client._cmd(["get", "pods"])
    assert "kubectl" in cmd
    assert "--kubeconfig" in cmd
    assert "--context" in cmd
    assert "-n" in cmd


def test_security_issue_dataclass():
    from k8s_monitor import SecurityIssue
    issue = SecurityIssue(
        resource="pod-1",
        namespace="default",
        severity="WARNING",
        rule="SEC003",
        message="Test message",
        remediation="Fix this"
    )
    assert issue.resource == "pod-1"
    assert issue.severity == "WARNING"


def test_pvc_info_dataclass():
    from k8s_monitor import PVCInfo
    pvc = PVCInfo(
        name="my-pvc",
        namespace="default",
        status="Bound",
        capacity="10Gi",
        storage_class="standard",
        bound=True
    )
    assert pvc.bound is True
    assert pvc.capacity == "10Gi"