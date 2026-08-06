# K8s Health Monitor

A lightweight CLI tool to monitor Kubernetes cluster health in real-time.

## Features

- **Node Health** — Check readiness, versions, roles
- **Pod Status** — Running, pending, failed pods with restart counts
- **Service Overview** — ClusterIP, LoadBalancer, NodePort services
- **Deployment Health** — Replica status, availability
- **Color-coded Output** — Quick visual health assessment
- **Demo Mode** — Works without a live cluster for testing

## Demo

```
$ python k8s_monitor.py
```

Runs with sample data when kubectl is not available.

## Requirements

- Python 3.8+
- `rich` library (auto-installed)
- Optional: `kubectl` for live cluster data

## Usage

```bash
# Demo mode (no cluster required)
python k8s_monitor.py

# With live cluster
kubectl cluster-info  # verify connection first
python k8s_monitor.py
```

## Architecture

```
k8s_monitor.py
├── KubectlClient      # kubectl wrapper (JSON output)
├── HealthAnalyzer     # Pod/Node/Service/Deployment analysis
├── Display            # Rich terminal UI
└── Colors             # ANSI color codes
```

## How It Works

1. **KubectlClient** runs `kubectl get nodes/pods/services/deployments -o json`
2. **HealthAnalyzer** processes the JSON and calculates health metrics
3. **Display** renders tables and summaries using `rich`

## Sample Output

```
┌──────────────────────────────────────────────┐
│  K8s Health Monitor v1.0                     │
│  2026-08-06 18:30:00                         │
└──────────────────────────────────────────────┘

Node Status
┌──────────────────┬────────┬──────────┬─────┬─────────┐
│ Name             │ Status │ Roles    │ Age │ Version │
├──────────────────┼────────┼──────────┼─────┼─────────┤
│ master-node-01   │ Ready  │ master   │ 7mo │ v1.30.2 │
│ worker-node-01   │ Ready  │ worker   │ 5mo │ v1.30.2 │
│ worker-node-02   │ Ready  │ worker   │ 4mo │ v1.30.2 │
│ worker-node-03   │NotReady│ worker   │ 3mo │ v1.30.2 │
└──────────────────┴────────┴──────────┴─────┴─────────┘

Cluster Health Summary
┌─────────────────┬────────────┐
│ Nodes           │ 3/4 ready  │
│ Pods            │ 8/10 run   │
│ Overall         │ ● WARNING  │
└─────────────────┴────────────┘
```

## Author

**Ankit** — CS Student | Open Source Enthusiast

## License

MIT
