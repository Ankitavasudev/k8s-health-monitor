#!/usr/bin/env python3
"""
K8s Health Monitor - Kubernetes Cluster Health Checker
A CLI tool to monitor Kubernetes cluster health in real-time.
Author: Ankit | GitHub: https://github.com/ankit
"""

import subprocess
import json
import sys
import os
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("Installing rich library...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich", "-q"])
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich import box


console = Console()

# ─── Colors ────────────────────────────────────────────────
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# ─── Kubectl Wrapper ───────────────────────────────────────
class KubectlClient:
    """Wrapper around kubectl commands."""

    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None):
        self.kubeconfig = kubeconfig
        self.context = context

    def _build_cmd(self, args: list) -> list:
        cmd = ["kubectl"]
        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])
        if self.context:
            cmd.extend(["--context", self.context])
        cmd.extend(args)
        return cmd

    def run(self, args: list, output_json: bool = True) -> Optional[dict]:
        cmd = self._build_cmd(args)
        if output_json:
            cmd.extend(["-o", "json"])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return None
            if output_json:
                return json.loads(result.stdout)
            return result.stdout
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            return None

    def get_nodes(self) -> list:
        data = self.run(["get", "nodes"])
        return data.get("items", []) if data else []

    def get_pods(self, namespace: str = "") -> list:
        if namespace:
            data = self.run(["get", "pods", "-n", namespace])
        else:
            data = self.run(["get", "pods", "--all-namespaces"])
        return data.get("items", []) if data else []

    def get_services(self, namespace: str = "") -> list:
        if namespace:
            data = self.run(["get", "services", "-n", namespace])
        else:
            data = self.run(["get", "services", "--all-namespaces"])
        return data.get("items", []) if data else []

    def get_namespaces(self) -> list:
        data = self.run(["get", "namespaces"])
        return data.get("items", []) if data else []

    def get_deployments(self, namespace: str = "") -> list:
        if namespace:
            data = self.run(["get", "deployments", "-n", namespace])
        else:
            data = self.run(["get", "deployments", "--all-namespaces"])
        return data.get("items", []) if data else []


# ─── Health Analyzer ───────────────────────────────────────
class HealthAnalyzer:
    """Analyzes cluster health and generates reports."""

    @staticmethod
    def analyze_nodes(nodes: list) -> dict:
        total = len(nodes)
        ready = sum(1 for n in nodes if any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in n.get("status", {}).get("conditions", [])
        ))
        not_ready = total - ready
        return {
            "total": total,
            "ready": ready,
            "not_ready": not_ready,
            "status": "HEALTHY" if not_ready == 0 else "WARNING" if not_ready <= 1 else "CRITICAL"
        }

    @staticmethod
    def analyze_pods(pods: list) -> dict:
        total = len(pods)
        running = sum(1 for p in pods if p.get("status", {}).get("phase") == "Running")
        pending = sum(1 for p in pods if p.get("status", {}).get("phase") == "Pending")
        failed = sum(1 for p in pods if p.get("status", {}).get("phase") == "Failed")
        succeeded = sum(1 for p in pods if p.get("status", {}).get("phase") == "Succeeded")
        unknown = total - running - pending - failed - succeeded

        # Check for restart loops
        restart_loops = 0
        for p in pods:
            for cs in p.get("status", {}).get("containerStatuses", []):
                if cs.get("restartCount", 0) > 5:
                    restart_loops += 1

        return {
            "total": total,
            "running": running,
            "pending": pending,
            "failed": failed,
            "succeeded": succeeded,
            "unknown": unknown,
            "restart_loops": restart_loops,
            "status": "HEALTHY" if failed == 0 and pending == 0 else "WARNING" if failed <= 2 else "CRITICAL"
        }

    @staticmethod
    def analyze_services(services: list) -> dict:
        total = len(services)
        with_endpoints = 0
        without_endpoints = 0
        for svc in services:
            svc_type = svc.get("spec", {}).get("type", "ClusterIP")
            if svc_type in ["LoadBalancer", "NodePort"]:
                with_endpoints += 1
            else:
                with_endpoints += 1
        return {
            "total": total,
            "status": "HEALTHY"
        }

    @staticmethod
    def analyze_deployments(deployments: list) -> dict:
        total = len(deployments)
        healthy = 0
        degraded = 0
        for d in deployments:
            status = d.get("status", {})
            desired = status.get("replicas", 0)
            ready = status.get("readyReplicas", 0)
            if desired == ready:
                healthy += 1
            else:
                degraded += 1
        return {
            "total": total,
            "healthy": healthy,
            "degraded": degraded,
            "status": "HEALTHY" if degraded == 0 else "WARNING" if degraded <= 1 else "CRITICAL"
        }


# ─── Display ───────────────────────────────────────────────
class Display:
    """Handles terminal display with rich formatting."""

    @staticmethod
    def banner():
        banner_text = r"""
 _    _      _                          __  __ _           _
| |  | |    | |                        |  \/  (_)         | |
| |__| | ___| |__   ___ _ __ _   _  __| \  / |_ _ __   __| | ___ _ __
|  __  |/ _ \ '_ \ / _ \ '__| | | |/ _` |\/| | | '_ \ / _` |/ _ \ '__|
| |  | |  __/ |_) |  __/ |  | |_| | (_| |  | | | | | | (_| |  __/ |
|_|  |_|\___|_.__/ \___|_|   \__, |\__,_|_| |_|_|_| |_|\__,_|\___|_|
                               __/ |
                              |___/
        """
        console.print(Panel(banner_text.strip(), style="bold cyan", box=box.SIMPLE))
        console.print(f"  [dim]Kubernetes Cluster Health Monitor v1.0[/dim]")
        console.print(f"  [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")

    @staticmethod
    def status_badge(status: str) -> str:
        badges = {
            "HEALTHY": "[bold green][OK] HEALTHY[/bold green]",
            "WARNING": "[bold yellow][!!] WARNING[/bold yellow]",
            "CRITICAL": "[bold red][XX] CRITICAL[/bold red]",
        }
        return badges.get(status, f"[bold white][--] {status}[/bold white]")

    @staticmethod
    def show_nodes(nodes: list, analysis: dict):
        table = Table(title="Node Status", box=box.ROUNDED, show_lines=True)
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Status", justify="center")
        table.add_column("Roles", style="dim")
        table.add_column("Age", style="dim")
        table.add_column("Version", style="green")

        for node in nodes:
            name = node["metadata"]["name"]
            labels = node["metadata"].get("labels", {})
            roles = [k.replace("node-role.kubernetes.io/", "") for k in labels if k.startswith("node-role.kubernetes.io/")]
            role_str = ", ".join(roles) if roles else "<none>"

            conditions = node.get("status", {}).get("conditions", [])
            is_ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
            status = "[green]Ready[/green]" if is_ready else "[red]NotReady[/red]"

            version = node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion", "unknown")
            age = _get_age(node["metadata"].get("creationTimestamp", ""))

            table.add_row(name, status, role_str, age, version)

        console.print(table)
        console.print(f"  Nodes: {analysis['ready']}/{analysis['total']} ready {Display.status_badge(analysis['status'])}\n")

    @staticmethod
    def show_pods(pods: list, analysis: dict):
        table = Table(title="Pod Status", box=box.ROUNDED, show_lines=True)
        table.add_column("Namespace", style="cyan", no_wrap=True)
        table.add_column("Name", style="white", max_width=40)
        table.add_column("Status", justify="center")
        table.add_column("Restarts", justify="center")
        table.add_column("Age", style="dim")

        for pod in pods[:30]:  # Show max 30 pods
            ns = pod["metadata"].get("namespace", "default")
            name = pod["metadata"]["name"]
            phase = pod.get("status", {}).get("phase", "Unknown")

            status_colors = {
                "Running": "green", "Pending": "yellow",
                "Failed": "red", "Succeeded": "blue", "Unknown": "dim"
            }
            color = status_colors.get(phase, "white")
            status = f"[{color}]{phase}[/{color}]"

            restarts = sum(
                cs.get("restartCount", 0)
                for cs in pod.get("status", {}).get("containerStatuses", [])
            )
            restart_str = f"[red]{restarts}[/red]" if restarts > 5 else str(restarts)

            age = _get_age(pod["metadata"].get("creationTimestamp", ""))
            table.add_row(ns, name, status, restart_str, age)

        if len(pods) > 30:
            console.print(f"  [dim]... and {len(pods) - 30} more pods[/dim]")

        console.print(table)
        console.print(f"  Pods: {analysis['running']}/{analysis['total']} running "
                      f"({analysis['pending']} pending, {analysis['failed']} failed) "
                      f"{Display.status_badge(analysis['status'])}\n")

    @staticmethod
    def show_services(services: list, analysis: dict):
        table = Table(title="Services", box=box.ROUNDED, show_lines=True)
        table.add_column("Namespace", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Cluster IP", style="dim")
        table.add_column("Ports", style="green")

        for svc in services[:20]:
            ns = svc["metadata"].get("namespace", "default")
            name = svc["metadata"]["name"]
            svc_type = svc.get("spec", {}).get("type", "ClusterIP")
            cluster_ip = svc.get("spec", {}).get("clusterIP", "None")
            ports = ", ".join(
                f"{p.get('port')}/{p.get('protocol', 'TCP')}"
                for p in svc.get("spec", {}).get("ports", [])
            )
            table.add_row(ns, name, svc_type, cluster_ip, ports or "-")

        console.print(table)
        console.print(f"  Services: {analysis['total']} total {Display.status_badge(analysis['status'])}\n")

    @staticmethod
    def show_deployments(deployments: list, analysis: dict):
        table = Table(title="Deployments", box=box.ROUNDED, show_lines=True)
        table.add_column("Namespace", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Ready", justify="center")
        table.add_column("Up-to-date", justify="center")
        table.add_column("Available", justify="center")
        table.add_column("Age", style="dim")

        for d in deployments[:20]:
            ns = d["metadata"].get("namespace", "default")
            name = d["metadata"]["name"]
            status = d.get("status", {})
            ready = f"{status.get('readyReplicas', 0)}/{status.get('replicas', 0)}"
            updated = status.get("updatedReplicas", 0)
            available = status.get("availableReplicas", 0)
            age = _get_age(d["metadata"].get("creationTimestamp", ""))

            ready_color = "green" if status.get("readyReplicas", 0) == status.get("replicas", 0) else "red"
            table.add_row(ns, name, f"[{ready_color}]{ready}[/{ready_color}]", str(updated), str(available), age)

        console.print(table)
        console.print(f"  Deployments: {analysis['healthy']}/{analysis['total']} healthy "
                      f"{Display.status_badge(analysis['status'])}\n")

    @staticmethod
    def show_summary(node_analysis: dict, pod_analysis: dict, svc_analysis: dict, deploy_analysis: dict):
        # Overall health
        statuses = [node_analysis["status"], pod_analysis["status"], svc_analysis["status"], deploy_analysis["status"]]
        if "CRITICAL" in statuses:
            overall = "CRITICAL"
        elif "WARNING" in statuses:
            overall = "WARNING"
        else:
            overall = "HEALTHY"

        summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        summary.add_column("Metric", style="bold")
        summary.add_column("Value", justify="right")

        summary.add_row("Nodes", f"{node_analysis['ready']}/{node_analysis['total']} ready")
        summary.add_row("Pods", f"{pod_analysis['running']}/{pod_analysis['total']} running")
        summary.add_row("Pods Failed", f"[red]{pod_analysis['failed']}[/red]" if pod_analysis['failed'] > 0 else "0")
        summary.add_row("Pending Pods", f"[yellow]{pod_analysis['pending']}[/yellow]" if pod_analysis['pending'] > 0 else "0")
        summary.add_row("Restart Loops", f"[red]{pod_analysis['restart_loops']}[/red]" if pod_analysis['restart_loops'] > 0 else "0")
        summary.add_row("Services", str(svc_analysis['total']))
        summary.add_row("Deployments", f"{deploy_analysis['healthy']}/{deploy_analysis['total']} healthy")
        summary.add_row("Overall", Display.status_badge(overall))

        console.print(Panel(summary, title="[bold]Cluster Health Summary[/bold]", border_style="cyan"))


# ─── Utilities ─────────────────────────────────────────────
def _get_age(timestamp: str) -> str:
    if not timestamp:
        return "unknown"
    try:
        created = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        now = datetime.now(created.tzinfo)
        delta = now - created
        days = delta.days
        hours = delta.seconds // 3600
        if days > 365:
            return f"{days // 365}y"
        elif days > 30:
            return f"{days // 30}mo"
        elif days > 0:
            return f"{days}d"
        elif hours > 0:
            return f"{hours}h"
        else:
            return f"{delta.seconds // 60}m"
    except Exception:
        return "unknown"


# ─── Demo Mode ─────────────────────────────────────────────
def generate_demo_data():
    """Generate demo data when kubectl is not available."""
    console.print("[yellow]kubectl not found — running in DEMO mode with sample data[/yellow]\n")

    nodes = [
        {"metadata": {"name": "master-node-01", "labels": {"node-role.kubernetes.io/master": ""}, "creationTimestamp": "2026-01-15T10:00:00Z"},
         "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.2"}}},
        {"metadata": {"name": "worker-node-01", "labels": {"node-role.kubernetes.io/worker": ""}, "creationTimestamp": "2026-02-20T14:30:00Z"},
         "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.2"}}},
        {"metadata": {"name": "worker-node-02", "labels": {"node-role.kubernetes.io/worker": ""}, "creationTimestamp": "2026-03-10T09:15:00Z"},
         "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.2"}}},
        {"metadata": {"name": "worker-node-03", "labels": {"node-role.kubernetes.io/worker": ""}, "creationTimestamp": "2026-04-05T16:45:00Z"},
         "status": {"conditions": [{"type": "Ready", "status": "False"}], "nodeInfo": {"kubeletVersion": "v1.30.2"}}},
    ]

    pods = [
        {"metadata": {"name": "kube-apiserver-master-01", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:05:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 2}]}},
        {"metadata": {"name": "kube-controller-master-01", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:05:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]}},
        {"metadata": {"name": "coredns-7f8d6b5c4-abc12", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:10:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 1}]}},
        {"metadata": {"name": "nginx-deployment-6d4f8b7c9-x7k2m", "namespace": "default", "creationTimestamp": "2026-05-01T08:00:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]}},
        {"metadata": {"name": "nginx-deployment-6d4f8b7c9-q9p3r", "namespace": "default", "creationTimestamp": "2026-05-01T08:00:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]}},
        {"metadata": {"name": "redis-master-0", "namespace": "default", "creationTimestamp": "2026-06-15T12:00:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]}},
        {"metadata": {"name": "redis-replica-0", "namespace": "default", "creationTimestamp": "2026-06-15T12:05:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]}},
        {"metadata": {"name": "pending-app-pod", "namespace": "default", "creationTimestamp": "2026-08-06T10:00:00Z"},
         "status": {"phase": "Pending", "containerStatuses": []}},
        {"metadata": {"name": "failed-job-abc", "namespace": "batch", "creationTimestamp": "2026-08-05T22:00:00Z"},
         "status": {"phase": "Failed", "containerStatuses": [{"restartCount": 10}]}},
        {"metadata": {"name": "etcd-master-01", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:03:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]}},
    ]

    services = [
        {"metadata": {"name": "kubernetes", "namespace": "default", "creationTimestamp": "2026-01-15T10:00:00Z"},
         "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.1", "ports": [{"port": 443, "protocol": "TCP"}]}},
        {"metadata": {"name": "kube-dns", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:00:00Z"},
         "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.10", "ports": [{"port": 53, "protocol": "UDP"}]}},
        {"metadata": {"name": "nginx-service", "namespace": "default", "creationTimestamp": "2026-05-01T08:05:00Z"},
         "spec": {"type": "LoadBalancer", "clusterIP": "10.98.12.34", "ports": [{"port": 80, "protocol": "TCP"}]}},
        {"metadata": {"name": "redis-service", "namespace": "default", "creationTimestamp": "2026-06-15T12:10:00Z"},
         "spec": {"type": "ClusterIP", "clusterIP": "10.99.56.78", "ports": [{"port": 6379, "protocol": "TCP"}]}},
    ]

    deployments = [
        {"metadata": {"name": "coredns", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:10:00Z"},
         "status": {"replicas": 2, "readyReplicas": 2, "updatedReplicas": 2, "availableReplicas": 2}},
        {"metadata": {"name": "nginx-deployment", "namespace": "default", "creationTimestamp": "2026-05-01T08:00:00Z"},
         "status": {"replicas": 3, "readyReplicas": 3, "updatedReplicas": 3, "availableReplicas": 3}},
        {"metadata": {"name": "redis-master", "namespace": "default", "creationTimestamp": "2026-06-15T12:00:00Z"},
         "status": {"replicas": 1, "readyReplicas": 1, "updatedReplicas": 1, "availableReplicas": 1}},
        {"metadata": {"name": "redis-replica", "namespace": "default", "creationTimestamp": "2026-06-15T12:05:00Z"},
         "status": {"replicas": 1, "readyReplicas": 1, "updatedReplicas": 1, "availableReplicas": 1}},
        {"metadata": {"name": "monitoring-agent", "namespace": "monitoring", "creationTimestamp": "2026-07-20T09:00:00Z"},
         "status": {"replicas": 2, "readyReplicas": 1, "updatedReplicas": 2, "availableReplicas": 1}},
    ]

    return nodes, pods, services, deployments


# ─── Main ──────────────────────────────────────────────────
def main():
    Display.banner()

    # Check for kubectl
    try:
        subprocess.run(["kubectl", "version", "--client"], capture_output=True, timeout=10)
        kubectl_available = True
    except Exception:
        kubectl_available = False

    if kubectl_available:
        client = KubectlClient()
        console.print("[green][OK] kubectl detected -- fetching live cluster data...[/green]\n")
        nodes = client.get_nodes()
        pods = client.get_pods()
        services = client.get_services()
        deployments = client.get_deployments()
    else:
        nodes, pods, services, deployments = generate_demo_data()

    # Analyze
    analyzer = HealthAnalyzer()
    node_analysis = analyzer.analyze_nodes(nodes)
    pod_analysis = analyzer.analyze_pods(pods)
    svc_analysis = analyzer.analyze_services(services)
    deploy_analysis = analyzer.analyze_deployments(deployments)

    # Display
    Display.show_nodes(nodes, node_analysis)
    Display.show_pods(pods, pod_analysis)
    Display.show_services(services, svc_analysis)
    Display.show_deployments(deployments, deploy_analysis)
    Display.show_summary(node_analysis, pod_analysis, svc_analysis, deploy_analysis)


if __name__ == "__main__":
    main()
