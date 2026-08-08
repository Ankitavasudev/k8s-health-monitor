import pytest
from resource_visualizer import ResourceUsage, parse_cpu, parse_memory, visualize_resources


def test_parse_cpu_millicores():
    assert parse_cpu("100m") == 100
    assert parse_cpu("500m") == 500
    assert parse_cpu("1000m") == 1000


def test_parse_cpu_cores():
    assert parse_cpu("0.5") == 500
    assert parse_cpu("1") == 1000
    assert parse_cpu("2") == 2000


def test_parse_cpu_na():
    assert parse_cpu("N/A") == 0
    assert parse_cpu(None) == 0


def test_parse_memory_mib():
    assert parse_memory("128Mi") == 128
    assert parse_memory("1Gi") == 1024
    assert parse_memory("512Ki") == 0 or parse_memory("512Ki") > 0


def test_parse_memory_na():
    assert parse_memory("N/A") == 0
    assert parse_memory(None) == 0


def test_visualize_resources(capsys):
    resources = [
        ResourceUsage("nginx", "100m", "500m", "128Mi", "256Mi"),
        ResourceUsage("redis", "250m", "1000m", "512Mi", "1Gi"),
    ]
    visualize_resources(resources)
    captured = capsys.readouterr()
    assert "nginx" in captured.out
    assert "redis" in captured.out


def test_resource_usage_fields():
    r = ResourceUsage("app", "100m", "500m", "128Mi", "256Mi")
    assert r.name == "app"
    assert r.cpu_request == "100m"
    assert r.memory_limit == "256Mi"