# k8s-health-monitor

[![CI](https://github.com/Ankitavasudev/k8s-health-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Ankitavasudev/k8s-health-monitor/actions)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A Kubernetes cluster health checker that scans for security issues, resource problems, and configuration misconfigurations.

## What It Does

`
$ python k8s_monitor.py check

=== K8s Health Monitor v3.0.0 ===

Security Analysis
┌──────────┬──────┬─────────────────┬──────────────────────────────────┐
│ Severity │ Rule │ Resource        │ Issue                            │
├──────────┼──────┼─────────────────┼──────────────────────────────────┤
│ CRITICAL │SEC001│ kube-system/pod │ Container runs PRIVILEGED        │
│ WARNING  │SEC003│ default/nginx   │ Container has writable rootfs    │
│ WARNING  │RBAC002│ cluster/admin  │ ClusterRole has wildcard verbs   │
└──────────┴──────┴─────────────────┴──────────────────────────────────┘

Persistent Volume Claims
┌───────────┬──────────┬────────┬──────────┬───────────────┐
│ Namespace │ Name     │ Status │ Capacity │ StorageClass  │
├───────────┼──────────┼────────┼──────────┼───────────────┤
│ default   │ data-pvc │ Bound  │ 10Gi     │ standard      │
│ default   │ backup   │ Pending│ N/A      │ standard      │
└───────────┴──────────┴────────┴──────────┴───────────────┘

Recommendations
* CRITICAL: 1 security issues — fix privileged containers immediately
* Namespace 'default' CPU at 75% — consider increasing limits
* 1 unbound PVCs found — check storage provisioner
`

## Features

- **Security Scanner** — Privileged containers, root users, RBAC wildcards, SA token auto-mount
- **PVC Analysis** — Bound/unbound status, capacity tracking, storage class monitoring
- **Resource Quotas** — CPU/Memory/Pod usage per namespace with threshold alerts
- **Network Policy Audit** — Detect namespaces without network policies
- **RBAC Analysis** — ClusterRole wildcard access detection
- **Recommendation Engine** — Auto-generates actionable fixes
- **Demo Mode** — Works without a live cluster using realistic test data

## Quick Start

`ash
# Install
git clone https://github.com/Ankitavasudev/k8s-health-monitor.git
cd k8s-health-monitor
pip install -r requirements.txt

# Run (demo mode if no kubectl)
python k8s_monitor.py check

# Run against live cluster
python k8s_monitor.py check --kubeconfig ~/.kube/config

# Export report
python k8s_monitor.py check -o report.json

# List namespaces
python k8s_monitor.py namespaces
`

## Architecture

`
k8s_monitor.py
├── KubectlClient       # kubectl wrapper with retry/timeout
├── SecurityScanner     # Privileged, RBAC, SA, NetworkPolicy
├── ResourceAnalyzer    # PVCs, Quotas, NetworkPolicies
├── HealthAnalyzer      # Nodes, Pods, Deployments
├── Recommender         # Auto-generates action items
└── Display             # Rich terminal UI
`

## Development

`ash
# Run tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=k8s_monitor

# Lint
flake8 k8s_monitor.py --max-line-length=120
`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License