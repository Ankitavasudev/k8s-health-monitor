import pytest
from namespace_compare import NamespaceStats, compare_namespaces, display_comparison


def test_compare_namespaces_empty():
    result = compare_namespaces([])
    assert "error" in result


def test_compare_namespaces_single():
    ns = [NamespaceStats("default", pods=5, services=2)]
    result = compare_namespaces(ns)
    assert result["total_namespaces"] == 1
    assert result["most_pods"].name == "default"


def test_compare_namespaces_multiple():
    ns = [
        NamespaceStats("default", pods=10, services=5, deployments=3),
        NamespaceStats("kube-system", pods=8, services=4, deployments=2),
        NamespaceStats("production", pods=25, services=10, deployments=8),
    ]
    result = compare_namespaces(ns)
    assert result["total_namespaces"] == 3
    assert result["most_pods"].name == "production"
    assert result["most_services"].name == "production"
    assert result["most_deployments"].name == "production"


def test_without_quotas():
    ns = [
        NamespaceStats("default", pods=5, resource_quotas=0),
        NamespaceStats("prod", pods=10, resource_quotas=2),
    ]
    result = compare_namespaces(ns)
    assert len(result["without_quotas"]) == 1
    assert result["without_quotas"][0].name == "default"


def test_without_netpol():
    ns = [
        NamespaceStats("default", pods=5, network_policies=0),
        NamespaceStats("prod", pods=10, network_policies=3),
    ]
    result = compare_namespaces(ns)
    assert len(result["without_netpol"]) == 1


def test_display_comparison(capsys):
    ns = [NamespaceStats("test", pods=5)]
    display_comparison(ns)
    captured = capsys.readouterr()
    assert "test" in captured.out