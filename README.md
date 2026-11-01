# k8s-health-monitor

A terminal dashboard for Kubernetes clusters: node/pod/deployment health,
a security scan, resource-request accounting, and a Prometheus endpoint.
It shells out to `kubectl` — no client library, no cluster-side agent.

```bash
python k8s_monitor.py --demo      # sample data, no cluster needed
python k8s_monitor.py             # your current kubeconfig context
```

![demo](https://img.shields.io/badge/demo-mode-blue) ![tests](https://img.shields.io/badge/tests-51%20passing-brightgreen)

## What it reports

| Section | What you get |
|---|---|
| Nodes | Ready / not-ready count, per-node status table |
| Pods | Phase breakdown, restart loops (>5 restarts), per-namespace table |
| Deployments | Ready vs desired replicas, degraded deployments |
| Services | Count and exposure type |
| Resources | Container requests/limits, unbounded containers, node capacity |
| Security | Findings by severity across pods, deployments, namespaces, services |
| Events | Recent `Warning` events with the object they belong to |

`--output json` prints the same analysis as machine-readable JSON (used by
`json_export.py` and CI), and `--output prometheus` prints an exposition-format
snapshot. `--exporter` keeps a live endpoint updated every 15 s.

## Security rules

Rule names are stable; severities are what the scanner assigns.

| Rule | Severity | Meaning |
|---|---|---|
| `PrivilegedContainer` | CRITICAL | `securityContext.privileged: true` |
| `AllCapabilities` | CRITICAL | container adds the `ALL` capability |
| `RunAsNonRoot` | HIGH | neither pod nor container sets `runAsNonRoot` |
| `DeploymentRunAsRoot` | HIGH | same check, on a deployment's pod template |
| `HostNetwork` | HIGH | pod shares the host network namespace |
| `HostPID` | HIGH | pod shares the host PID namespace |
| `NoResourceLimits` | MEDIUM | container declares no `resources.limits` |
| `NoPodSecurity` | MEDIUM | namespace has no `pod-security.kubernetes.io/enforce` label |
| `WritableRootFS` | LOW | `readOnlyRootFilesystem` is not set |
| `LoadBalancerExposure` | LOW | service type is `LoadBalancer` |

Demo mode intentionally includes one privileged pod, one pending pod, a failing
node and a degraded deployment so every branch of the UI is visible.

## Install

```bash
git clone https://github.com/Ankitavasudev/k8s-health-monitor
cd k8s-health-monitor
pip install -r requirements.txt      # rich, requests
```

Python 3.9+. Running against a real cluster also needs `kubectl` on `PATH` and a
kubeconfig; `--demo` needs neither.

## Usage

```bash

# Full scan against the current context
python k8s_monitor.py

# A specific kubeconfig / context / namespace
python k8s_monitor.py --kubeconfig ~/.kube/prod --context prod --namespace payments

# Skip the security scan
python k8s_monitor.py --no-security

# Machine-readable, and Prometheus
python k8s_monitor.py --output json
python k8s_monitor.py --output prometheus
python k8s_monitor.py --exporter --exporter-port 9090

# Sample data when there is no cluster around
python k8s_monitor.py --demo
```

Exit codes: `0` = scan completed, `2` = the cluster could not be read
(bad kubeconfig, wrong context, API server down). An unreachable cluster is
reported as `UNKNOWN`, never as `HEALTHY` — a `kubectl` call that fails returns
an empty list, which would otherwise look like a perfectly healthy cluster.

## Layout

```
k8s_monitor.py          KubectlClient + SecurityScanner + ResourceAnalyzer
                        + HealthAnalyzer + Display + PrometheusExporter
namespace_compare.py    Compare two namespaces side by side
resource_visualizer.py  Rich bar charts for CPU/memory
cli.py                  Subcommands: monitor / compare / export / benchmark
json_export.py          JSON report writer
benchmark.py            Fake-data timing harness
tests/                  pytest suite (no cluster required)
```

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

The tests never touch a real cluster: every analyzer is a pure function over
the JSON objects `kubectl get -o json` returns, and the kubectl client is
exercised with a monkeypatched `subprocess.run`.

## License

MIT — see [LICENSE](LICENSE).
