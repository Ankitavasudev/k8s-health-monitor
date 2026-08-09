# K8s Health Monitor v3.0

> Advanced Kubernetes cluster health checker with security scanning, resource visualization, and namespace comparison.

[![CI](https://github.com/Ankitavasudev/k8s-health-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Ankitavasudev/k8s-health-monitor/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- **Security Scanner** - Detects privileged containers, root users, writable rootfs, privilege escalation
- **Resource Analyzer** - Node health status, CPU/memory usage tracking
- **Health Analyzer** - Pod phase analysis (Running, Pending, Failed)
- **Namespace Comparison** - Side-by-side namespace resource comparison
- **Resource Visualizer** - Rich terminal bar charts for CPU/memory usage
- **JSON Export** - Machine-readable output for CI/CD pipelines
- **CLI Interface** - Multiple subcommands for different analysis tasks

## Quick Start

```bash
# Install
git clone https://github.com/Ankitavasudev/k8s-health-monitor.git
cd k8s-health-monitor
pip install -r requirements.txt

# Run health monitor
python k8s_monitor.py

# Compare namespaces
python namespace_compare.py default kube-system

# Visualize resources
python resource_visualizer.py

# Export to JSON
python json_export.py -o report.json
```

## CLI Usage

```bash
# Full cluster scan
python cli.py monitor

# Compare namespaces
python cli.py compare

# Run benchmarks
python cli.py benchmark

# Export results
python cli.py export --format json --output results.json
```

## Security Rules

| Rule | Severity | Description |
|------|----------|-------------|
| SEC001 | CRITICAL | Privileged container detected |
| SEC002 | CRITICAL | Container running as root |
| SEC003 | WARNING | Writable root filesystem |
| SEC004 | WARNING | Privilege escalation allowed |

## Architecture

```
k8s-health-monitor/
├── k8s_monitor.py          # Core monitor with SecurityScanner, ResourceAnalyzer, HealthAnalyzer
├── namespace_compare.py    # Namespace comparison tool
├── resource_visualizer.py  # Rich terminal visualization
├── json_export.py          # JSON export utilities
├── benchmark.py            # Performance benchmarking
├── cli.py                  # Unified CLI interface
└── tests/                  # Unit tests
```

## Tech Stack

- **Python 3.9+** - Core language
- **Rich** - Terminal UI (tables, panels, progress bars)
- **Kubernetes API** - Cluster data via kubectl
- **pytest** - Testing framework
- **flake8** - Code linting

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.