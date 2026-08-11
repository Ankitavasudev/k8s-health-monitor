#!/usr/bin/env python3
"""
K8s Health Monitor - Advanced Kubernetes Cluster Health Checker
Features: Security scanning, resource analysis, Prometheus export, rich CLI
Author: Ankita Salaria | GitHub: https://github.com/Ankitavasudev
"""

import subprocess
import json
import sys
import os
import time
import re
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
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
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box

console = Console()


# â”€â”€â”€ Kubectl Wrapper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class KubectlClient:
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

    def get_cluster_info(self) -> Optional[dict]:
        return self.run(["cluster-info"], output_json=False)

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

    def get_events(self) -> list:
        data = self.run(["get", "events", "--all-namespaces"])
        return data.get("items", []) if data else []

    def get_resource_quotas(self) -> list:
        data = self.run(["get", "resourcequotas", "--all-namespaces"])
        return data.get("items", []) if data else []

    def get_network_policies(self) -> list:
        data = self.run(["get", "networkpolicies", "--all-namespaces"])
        return data.get("items", []) if data else []

    def get_service_accounts(self) -> list:
        data = self.run(["get", "serviceaccounts", "--all-namespaces"])
        return data.get("items", []) if data else []


# â”€â”€â”€ Security Scanner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class SecurityScanner:
    """Scans Kubernetes resources for security misconfigurations."""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def scan_pods(self, pods: list) -> List[Dict]:
        for pod in pods:
            ns = pod["metadata"].get("namespace", "default")
            name = pod["metadata"]["name"]
            spec = pod.get("spec", {})
            security = spec.get("securityContext", {})

            for container in spec.get("containers", []):
                cs = container.get("securityContext", {})
                if not security.get("runAsNonRoot") and not cs.get("runAsNonRoot"):
                    self.findings.append({
                        "resource": f"{ns}/{name}",
                        "container": container["name"],
                        "severity": "HIGH",
                        "rule": "RunAsNonRoot",
                        "message": "Container runs as root"
                    })

                if cs.get("privileged"):
                    self.findings.append({
                        "resource": f"{ns}/{name}",
                        "container": container["name"],
                        "severity": "CRITICAL",
                        "rule": "PrivilegedContainer",
                        "message": "Container runs in privileged mode"
                    })

                caps = cs.get("capabilities", {})
                if "ALL" in caps.get("add", []):
                    self.findings.append({
                        "resource": f"{ns}/{name}",
                        "container": container["name"],
                        "severity": "CRITICAL",
                        "rule": "AllCapabilities",
                        "message": "Container has ALL capabilities"
                    })

                if not cs.get("readOnlyRootFilesystem"):
                    self.findings.append({
                        "resource": f"{ns}/{name}",
                        "container": container["name"],
                        "severity": "LOW",
                        "rule": "WritableRootFS",
                        "message": "Root filesystem is writable"
                    })

                limits = container.get("resources", {}).get("limits", {})
                if not limits:
                    self.findings.append({
                        "resource": f"{ns}/{name}",
                        "container": container["name"],
                        "severity": "MEDIUM",
                        "rule": "NoResourceLimits",
                        "message": "No resource limits defined"
                    })

            if spec.get("hostNetwork"):
                self.findings.append({
                    "resource": f"{ns}/{name}",
                    "container": "-",
                    "severity": "HIGH",
                    "rule": "HostNetwork",
                    "message": "Pod uses host network"
                })

            if spec.get("hostPID"):
                self.findings.append({
                    "resource": f"{ns}/{name}",
                    "container": "-",
                    "severity": "HIGH",
                    "rule": "HostPID",
                    "message": "Pod uses host PID namespace"
                })

        return self.findings

    def scan_deployments(self, deployments: list) -> List[Dict]:
        for dep in deployments:
            ns = dep["metadata"].get("namespace", "default")
            name = dep["metadata"]["name"]
            spec = dep.get("spec", {}).get("template", {}).get("spec", {})
            security = spec.get("securityContext", {})

            for container in spec.get("containers", []):
                cs = container.get("securityContext", {})
                if not security.get("runAsNonRoot") and not cs.get("runAsNonRoot"):
                    self.findings.append({
                        "resource": f"{ns}/{name}",
                        "container": container["name"],
                        "severity": "HIGH",
                        "rule": "DeploymentRunAsRoot",
                        "message": "Deployment runs as root"
                    })

        return self.findings

    def scan_namespaces(self, namespaces: list) -> List[Dict]:
        for ns in namespaces:
            name = ns["metadata"]["name"]
            if name in ["kube-system", "kube-public", "kube-node-lease"]:
                continue
            labels = ns.get("metadata", {}).get("labels", {})
            if not labels.get("pod-security.kubernetes.io/enforce"):
                self.findings.append({
                    "resource": f"namespace/{name}",
                    "container": "-",
                    "severity": "MEDIUM",
                    "rule": "NoPodSecurity",
                    "message": "Namespace has no pod security policy"
                })
        return self.findings

    def scan_services(self, services: list) -> List[Dict]:
        for svc in services:
            ns = svc["metadata"].get("namespace", "default")
            name = svc["metadata"]["name"]
            svc_type = svc.get("spec", {}).get("type", "ClusterIP")
            if svc_type == "LoadBalancer":
                self.findings.append({
                    "resource": f"{ns}/{name}",
                    "container": "-",
                    "severity": "LOW",
                    "rule": "LoadBalancerExposure",
                    "message": "Service exposed via LoadBalancer"
                })
        return self.findings

    def get_summary(self) -> Dict:
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            severity = f.get("severity", "LOW")
            summary[severity] = summary.get(severity, 0) + 1
        return summary


# â”€â”€â”€ Resource Analyzer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class ResourceAnalyzer:
    """Analyzes resource usage and quotas across the cluster."""

    def analyze_nodes(self, nodes: list) -> Dict:
        result = {
            "total": len(nodes),
            "cpu_capacity": 0,
            "memory_capacity": 0,
            "pods_capacity": 0,
        }
        for node in nodes:
            allocatable = node.get("status", {}).get("allocatable", {})
            cpu = allocatable.get("cpu", "0")
            mem = allocatable.get("memory", "0")
            pods = allocatable.get("pods", "0")
            result["cpu_capacity"] += self._parse_cpu(cpu)
            result["memory_capacity"] += self._parse_memory(mem)
            result["pods_capacity"] += int(pods)
        return result

    def analyze_pod_resources(self, pods: list) -> Dict:
        result = {
            "total_containers": 0,
            "containers_with_limits": 0,
            "containers_with_requests": 0,
            "total_cpu_requests": 0,
            "total_cpu_limits": 0,
            "total_mem_requests": 0,
            "total_mem_limits": 0,
            "unbounded_containers": 0,
        }
        for pod in pods:
            for container in pod.get("spec", {}).get("containers", []):
                result["total_containers"] += 1
                resources = container.get("resources", {})
                requests = resources.get("requests", {})
                limits = resources.get("limits", {})
                if requests:
                    result["containers_with_requests"] += 1
                    result["total_cpu_requests"] += self._parse_cpu(requests.get("cpu", "0"))
                    result["total_mem_requests"] += self._parse_memory(requests.get("memory", "0"))
                if limits:
                    result["containers_with_limits"] += 1
                    result["total_cpu_limits"] += self._parse_cpu(limits.get("cpu", "0"))
                    result["total_mem_limits"] += self._parse_memory(limits.get("memory", "0"))
                if not requests and not limits:
                    result["unbounded_containers"] += 1
        return result

    def analyze_namespaces(self, namespaces: list) -> List[Dict]:
        ns_stats = []
        for ns in namespaces:
            name = ns["metadata"]["name"]
            status = ns.get("status", {}).get("phase", "Unknown")
            ns_stats.append({"name": name, "phase": status})
        return ns_stats

    @staticmethod
    def _parse_cpu(cpu_str: str) -> float:
        if cpu_str.endswith("m"):
            return float(cpu_str[:-1]) / 1000
        return float(cpu_str)

    @staticmethod
    def _parse_memory(mem_str: str) -> float:
        multipliers = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4}
        for suffix, mult in multipliers.items():
            if mem_str.endswith(suffix):
                return float(mem_str[:-len(suffix)]) * mult
        return float(mem_str)


# â”€â”€â”€ Health Analyzer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class HealthAnalyzer:
    def analyze_nodes(self, nodes: list) -> dict:
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

    def analyze_pods(self, pods: list) -> dict:
        total = len(pods)
        running = sum(1 for p in pods if p.get("status", {}).get("phase") == "Running")
        pending = sum(1 for p in pods if p.get("status", {}).get("phase") == "Pending")
        failed = sum(1 for p in pods if p.get("status", {}).get("phase") == "Failed")
        succeeded = sum(1 for p in pods if p.get("status", {}).get("phase") == "Succeeded")
        unknown = total - running - pending - failed - succeeded
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

    def analyze_services(self, services: list) -> dict:
        return {"total": len(services), "status": "HEALTHY"}

    def analyze_deployments(self, deployments: list) -> dict:
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

    def analyze_events(self, events: list) -> Dict:
        warning_events = [e for e in events if e.get("type") == "Warning"]
        return {
            "total": len(events),
            "warnings": len(warning_events),
            "warning_details": [
                {
                    "reason": e.get("reason"),
                    "message": e.get("message", "")[:100],
                    "object": f"{e.get('involvedObject', {}).get('namespace', '')}/{e.get('involvedObject', {}).get('name', '')}"
                }
                for e in warning_events[:10]
            ]
        }


# â”€â”€â”€ Display â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class Display:
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
        console.print(f"  [dim]Kubernetes Cluster Health Monitor v3.0[/dim]")
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
    def show_nodes(nodes, analysis):
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
    def show_pods(pods, analysis):
        table = Table(title="Pod Status", box=box.ROUNDED, show_lines=True)
        table.add_column("Namespace", style="cyan", no_wrap=True)
        table.add_column("Name", style="white", max_width=40)
        table.add_column("Status", justify="center")
        table.add_column("Restarts", justify="center")
        table.add_column("Age", style="dim")
        for pod in pods[:30]:
            ns = pod["metadata"].get("namespace", "default")
            name = pod["metadata"]["name"]
            phase = pod.get("status", {}).get("phase", "Unknown")
            status_colors = {"Running": "green", "Pending": "yellow", "Failed": "red", "Succeeded": "blue", "Unknown": "dim"}
            color = status_colors.get(phase, "white")
            status = f"[{color}]{phase}[/{color}]"
            restarts = sum(cs.get("restartCount", 0) for cs in pod.get("status", {}).get("containerStatuses", []))
            restart_str = f"[red]{restarts}[/red]" if restarts > 5 else str(restarts)
            age = _get_age(pod["metadata"].get("creationTimestamp", ""))
            table.add_row(ns, name, status, restart_str, age)
        if len(pods) > 30:
            console.print(f"  [dim]... and {len(pods) - 30} more pods[/dim]")
        console.print(table)
        console.print(f"  Pods: {analysis['running']}/{analysis['total']} running ({analysis['pending']} pending, {analysis['failed']} failed) {Display.status_badge(analysis['status'])}\n")

    @staticmethod
    def show_services(services, analysis):
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
            ports = ", ".join(f"{p.get('port')}/{p.get('protocol', 'TCP')}" for p in svc.get("spec", {}).get("ports", []))
            table.add_row(ns, name, svc_type, cluster_ip, ports or "-")
        console.print(table)
        console.print(f"  Services: {analysis['total']} total {Display.status_badge(analysis['status'])}\n")

    @staticmethod
    def show_deployments(deployments, analysis):
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
        console.print(f"  Deployments: {analysis['healthy']}/{analysis['total']} healthy {Display.status_badge(analysis['status'])}\n")

    @staticmethod
    def show_security(findings, summary):
        if not findings:
            console.print(Panel("[bold green]No security issues found![/bold green]", title="Security Scan", border_style="green"))
            return
        table = Table(title="Security Findings", box=box.ROUNDED, show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Resource", style="cyan", max_width=35)
        table.add_column("Rule", style="white")
        table.add_column("Message", style="dim")
        severity_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "white"}
        for f in findings:
            color = severity_colors.get(f["severity"], "white")
            table.add_row(f"[{color}]{f['severity']}[/{color}]", f["resource"], f["rule"], f["message"])
        console.print(table)
        console.print(f"  Critical: {summary['CRITICAL']} | High: {summary['HIGH']} | Medium: {summary['MEDIUM']} | Low: {summary['LOW']}\n")

    @staticmethod
    def show_resources(resource_analysis):
        table = Table(title="Resource Analysis", box=box.ROUNDED, show_lines=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green", justify="right")
        table.add_row("Total Containers", str(resource_analysis["total_containers"]))
        table.add_row("With Limits", str(resource_analysis["containers_with_limits"]))
        table.add_row("With Requests", str(resource_analysis["containers_with_requests"]))
        table.add_row("Unbounded", f"[yellow]{resource_analysis['unbounded_containers']}[/yellow]" if resource_analysis["unbounded_containers"] > 0 else "0")
        table.add_row("CPU Requests", f"{resource_analysis['total_cpu_requests']:.2f} cores")
        table.add_row("CPU Limits", f"{resource_analysis['total_cpu_limits']:.2f} cores")
        table.add_row("Memory Requests", _format_bytes(resource_analysis["total_mem_requests"]))
        table.add_row("Memory Limits", _format_bytes(resource_analysis["total_mem_limits"]))
        console.print(table)
        console.print()

    @staticmethod
    def show_events(event_analysis):
        if event_analysis["warnings"] > 0:
            table = Table(title="Warning Events", box=box.ROUNDED, show_lines=True)
            table.add_column("Object", style="cyan", max_width=30)
            table.add_column("Reason", style="white")
            table.add_column("Message", style="dim", max_width=50)
            for ev in event_analysis["warning_details"]:
                table.add_row(ev["object"], ev["reason"], ev["message"])
            console.print(table)
            console.print(f"  Total: {event_analysis['total']} | Warnings: {event_analysis['warnings']}\n")

    @staticmethod
    def show_summary(node_analysis, pod_analysis, svc_analysis, deploy_analysis, security_summary, event_analysis):
        statuses = [node_analysis["status"], pod_analysis["status"], svc_analysis["status"], deploy_analysis["status"]]
        if "CRITICAL" in statuses or security_summary.get("CRITICAL", 0) > 0:
            overall = "CRITICAL"
        elif "WARNING" in statuses or security_summary.get("HIGH", 0) > 0:
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
        total_security = sum(security_summary.values())
        summary.add_row("Security Issues", f"[red]{total_security}[/red]" if total_security > 0 else "[green]0[/green]")
        summary.add_row("Warning Events", f"[yellow]{event_analysis['warnings']}[/yellow]" if event_analysis['warnings'] > 0 else "0")
        summary.add_row("Overall", Display.status_badge(overall))
        console.print(Panel(summary, title="[bold]Cluster Health Summary[/bold]", border_style="cyan"))


# â”€â”€â”€ Prometheus Exporter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class PrometheusExporter:
    """Exposes cluster metrics in Prometheus format via HTTP."""

    def __init__(self, port: int = 9090):
        self.port = port
        self.metrics = {}

    def update_metrics(self, nodes, pods, services, deployments, security_summary, resource_analysis):
        self.metrics = {
            "cluster_nodes_total": len(nodes),
            "cluster_nodes_ready": sum(1 for n in nodes if any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in n.get("status", {}).get("conditions", [])
            )),
            "cluster_pods_total": len(pods),
            "cluster_pods_running": sum(1 for p in pods if p.get("status", {}).get("phase") == "Running"),
            "cluster_pods_pending": sum(1 for p in pods if p.get("status", {}).get("phase") == "Pending"),
            "cluster_pods_failed": sum(1 for p in pods if p.get("status", {}).get("phase") == "Failed"),
            "cluster_services_total": len(services),
            "cluster_deployments_total": len(deployments),
            "cluster_deployments_healthy": sum(1 for d in deployments if d.get("status", {}).get("replicas", 0) == d.get("status", {}).get("readyReplicas", 0)),
            "cluster_security_critical": security_summary.get("CRITICAL", 0),
            "cluster_security_high": security_summary.get("HIGH", 0),
            "cluster_security_medium": security_summary.get("MEDIUM", 0),
            "cluster_security_low": security_summary.get("LOW", 0),
            "cluster_containers_total": resource_analysis.get("total_containers", 0),
            "cluster_containers_unbounded": resource_analysis.get("unbounded_containers", 0),
            "cluster_cpu_requests_total": resource_analysis.get("total_cpu_requests", 0),
            "cluster_cpu_limits_total": resource_analysis.get("total_cpu_limits", 0),
            "cluster_memory_requests_bytes": resource_analysis.get("total_mem_requests", 0),
            "cluster_memory_limits_bytes": resource_analysis.get("total_mem_limits", 0),
            "cluster_nodes_cpu_capacity": resource_analysis.get("cpu_capacity", 0),
            "cluster_nodes_memory_capacity": resource_analysis.get("memory_capacity", 0),
        }

    def generate_output(self) -> str:
        lines = []
        for name, value in sorted(self.metrics.items()):
            lines.append(f"# HELP {name} Kubernetes cluster metric")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")
        return "\n".join(lines)


# â”€â”€â”€ Utilities â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


def _format_bytes(b: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# â”€â”€â”€ Demo Mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def generate_demo_data():
    console.print("[yellow]kubectl not found -- running in DEMO mode with sample data[/yellow]\n")
    nodes = [
        {"metadata": {"name": "master-node-01", "labels": {"node-role.kubernetes.io/master": ""}, "creationTimestamp": "2026-01-15T10:00:00Z"},
         "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.2"}, "allocatable": {"cpu": "4000m", "memory": "16384Mi", "pods": "110"}}},
        {"metadata": {"name": "worker-node-01", "labels": {"node-role.kubernetes.io/worker": ""}, "creationTimestamp": "2026-02-20T14:30:00Z"},
         "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.2"}, "allocatable": {"cpu": "8000m", "memory": "32768Mi", "pods": "110"}}},
        {"metadata": {"name": "worker-node-02", "labels": {"node-role.kubernetes.io/worker": ""}, "creationTimestamp": "2026-03-10T09:15:00Z"},
         "status": {"conditions": [{"type": "Ready", "status": "True"}], "nodeInfo": {"kubeletVersion": "v1.30.2"}, "allocatable": {"cpu": "8000m", "memory": "32768Mi", "pods": "110"}}},
        {"metadata": {"name": "worker-node-03", "labels": {"node-role.kubernetes.io/worker": ""}, "creationTimestamp": "2026-04-05T16:45:00Z"},
         "status": {"conditions": [{"type": "Ready", "status": "False"}], "nodeInfo": {"kubeletVersion": "v1.30.2"}, "allocatable": {"cpu": "8000m", "memory": "32768Mi", "pods": "110"}}},
    ]

    pods = [
        {"metadata": {"name": "kube-apiserver-master-01", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:05:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 2}]},
         "spec": {"containers": [{"name": "apiserver", "resources": {"limits": {"cpu": "2000m", "memory": "2Gi"}, "requests": {"cpu": "1000m", "memory": "1Gi"}}}]}},
        {"metadata": {"name": "kube-controller-master-01", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:05:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]},
         "spec": {"containers": [{"name": "controller", "resources": {"limits": {"cpu": "1000m", "memory": "1Gi"}, "requests": {"cpu": "500m", "memory": "512Mi"}}}]}},
        {"metadata": {"name": "coredns-7f8d6b5c4-abc12", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:10:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 1}]},
         "spec": {"containers": [{"name": "coredns", "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}, "requests": {"cpu": "100m", "memory": "128Mi"}}}]}},
        {"metadata": {"name": "nginx-deployment-6d4f8b7c9-x7k2m", "namespace": "default", "creationTimestamp": "2026-05-01T08:00:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]},
         "spec": {"securityContext": {"runAsNonRoot": True}, "containers": [{"name": "nginx", "securityContext": {"readOnlyRootFilesystem": True}, "resources": {"limits": {"cpu": "200m", "memory": "256Mi"}, "requests": {"cpu": "100m", "memory": "128Mi"}}}]}},
        {"metadata": {"name": "nginx-deployment-6d4f8b7c9-q9p3r", "namespace": "default", "creationTimestamp": "2026-05-01T08:00:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]},
         "spec": {"containers": [{"name": "nginx", "resources": {}, "securityContext": {}}}]}},
        {"metadata": {"name": "redis-master-0", "namespace": "default", "creationTimestamp": "2026-06-15T12:00:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]},
         "spec": {"containers": [{"name": "redis", "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}, "requests": {"cpu": "250m", "memory": "256Mi"}}}]}},
        {"metadata": {"name": "redis-replica-0", "namespace": "default", "creationTimestamp": "2026-06-15T12:05:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]},
         "spec": {"containers": [{"name": "redis", "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}, "requests": {"cpu": "250m", "memory": "256Mi"}}}]}},
        {"metadata": {"name": "pending-app-pod", "namespace": "default", "creationTimestamp": "2026-08-06T10:00:00Z"},
         "status": {"phase": "Pending", "containerStatuses": []},
         "spec": {"containers": [{"name": "app", "resources": {}}]}},
        {"metadata": {"name": "failed-job-abc", "namespace": "batch", "creationTimestamp": "2026-08-05T22:00:00Z"},
         "status": {"phase": "Failed", "containerStatuses": [{"restartCount": 10}]},
         "spec": {"containers": [{"name": "job", "resources": {}}]}},
        {"metadata": {"name": "etcd-master-01", "namespace": "kube-system", "creationTimestamp": "2026-01-15T10:03:00Z"},
         "status": {"phase": "Running", "containerStatuses": [{"restartCount": 0}]},
         "spec": {"containers": [{"name": "etcd", "resources": {"limits": {"cpu": "2000m", "memory": "2Gi"}, "requests": {"cpu": "1000m", "memory": "1Gi"}}}]}},
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
         "status": {"replicas": 2, "readyReplicas": 2, "updatedReplicas": 2, "availableReplicas": 2},
         "spec": {"template": {"spec": {"containers": [{"name": "coredns", "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}}}]}}}},
        {"metadata": {"name": "nginx-deployment", "namespace": "default", "creationTimestamp": "2026-05-01T08:00:00Z"},
         "status": {"replicas": 3, "readyReplicas": 3, "updatedReplicas": 3, "availableReplicas": 3},
         "spec": {"template": {"spec": {"containers": [{"name": "nginx", "resources": {}}]}}}},
        {"metadata": {"name": "redis-master", "namespace": "default", "creationTimestamp": "2026-06-15T12:00:00Z"},
         "status": {"replicas": 1, "readyReplicas": 1, "updatedReplicas": 1, "availableReplicas": 1},
         "spec": {"template": {"spec": {"containers": [{"name": "redis", "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}}}]}}}},
        {"metadata": {"name": "redis-replica", "namespace": "default", "creationTimestamp": "2026-06-15T12:05:00Z"},
         "status": {"replicas": 1, "readyReplicas": 1, "updatedReplicas": 1, "availableReplicas": 1},
         "spec": {"template": {"spec": {"containers": [{"name": "redis", "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}}}]}}}},
        {"metadata": {"name": "monitoring-agent", "namespace": "monitoring", "creationTimestamp": "2026-07-20T09:00:00Z"},
         "status": {"replicas": 2, "readyReplicas": 1, "updatedReplicas": 2, "availableReplicas": 1},
         "spec": {"template": {"spec": {"containers": [{"name": "monitor", "resources": {}}]}}}},
    ]

    events = [
        {"type": "Warning", "reason": "BackOff", "message": "Back-off restarting failed container", "involvedObject": {"namespace": "default", "name": "failed-job-abc"}},
        {"type": "Warning", "reason": "Unhealthy", "message": "Readiness probe failed", "involvedObject": {"namespace": "monitoring", "name": "monitoring-agent"}},
        {"type": "Normal", "reason": "Scheduled", "message": "Successfully assigned pod", "involvedObject": {"namespace": "default", "name": "nginx-deployment"}},
    ]

    namespaces = [
        {"metadata": {"name": "default", "labels": {}}},
        {"metadata": {"name": "kube-system", "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}},
        {"metadata": {"name": "monitoring", "labels": {}}},
    ]

    return nodes, pods, services, deployments, events, namespaces


# â”€â”€â”€ Main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def main():
    Display.banner()

    import argparse
    parser = argparse.ArgumentParser(description="Kubernetes Cluster Health Monitor")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--context", help="Kubernetes context to use")
    parser.add_argument("--namespace", "-n", help="Specific namespace to scan")
    parser.add_argument("--output", choices=["text", "json", "prometheus"], default="text", help="Output format")
    parser.add_argument("--exporter", action="store_true", help="Start Prometheus exporter")
    parser.add_argument("--exporter-port", type=int, default=9090, help="Prometheus exporter port")
    parser.add_argument("--security", action="store_true", default=True, help="Run security scan")
    parser.add_argument("--no-security", action="store_false", dest="security")
    args = parser.parse_args()

    if args.exporter:
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            console.print(f"[bold green]Starting Prometheus exporter on port {args.exporter_port}[/bold green]")

            kubectl = KubectlClient(kubeconfig=args.kubeconfig, context=args.context)
            exporter = PrometheusExporter(port=args.exporter_port)

            while True:
                nodes = kubectl.get_nodes()
                pods = kubectl.get_pods()
                services = kubectl.get_services()
                deployments = kubectl.get_deployments()
                security = SecurityScanner()
                security.scan_pods(pods)
                security.scan_deployments(deployments)
                security_summary = security.get_summary()
                resource_analyzer = ResourceAnalyzer()
                resource_analysis = resource_analyzer.analyze_pod_resources(pods)
                exporter.update_metrics(nodes, pods, services, deployments, security_summary, resource_analysis)
                time.sleep(15)
        except KeyboardInterrupt:
            console.print("\n[yellow]Exporter stopped[/yellow]")
        return

    try:
        subprocess.run(["kubectl", "version", "--client"], capture_output=True, timeout=10)
        kubectl_available = True
    except Exception:
        kubectl_available = False

    if kubectl_available:
        client = KubectlClient(kubeconfig=args.kubeconfig, context=args.context)
        console.print("[green][OK] kubectl detected -- fetching live cluster data...[/green]\n")
        nodes = client.get_nodes()
        pods = client.get_pods(args.namespace or "")
        services = client.get_services(args.namespace or "")
        deployments = client.get_deployments(args.namespace or "")
        events = client.get_events()
        namespaces = client.get_namespaces()
    else:
        nodes, pods, services, deployments, events, namespaces = generate_demo_data()

    analyzer = HealthAnalyzer()
    node_analysis = analyzer.analyze_nodes(nodes)
    pod_analysis = analyzer.analyze_pods(pods)
    svc_analysis = analyzer.analyze_services(services)
    deploy_analysis = analyzer.analyze_deployments(deployments)
    event_analysis = analyzer.analyze_events(events)

    Display.show_nodes(nodes, node_analysis)
    Display.show_pods(pods, pod_analysis)
    Display.show_services(services, svc_analysis)
    Display.show_deployments(deployments, deploy_analysis)
    Display.show_events(event_analysis)

    resource_analyzer = ResourceAnalyzer()
    node_resources = resource_analyzer.analyze_nodes(nodes)
    pod_resources = resource_analyzer.analyze_pod_resources(pods)
    Display.show_resources(pod_resources)

    if args.security:
        security = SecurityScanner()
        security.scan_pods(pods)
        security.scan_deployments(deployments)
        security.scan_namespaces(namespaces)
        security.scan_services(services)
        security_summary = security.get_summary()
        Display.show_security(security.findings, security_summary)
    else:
        security_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    Display.show_summary(node_analysis, pod_analysis, svc_analysis, deploy_analysis, security_summary, event_analysis)

    if args.output == "json":
        result = {
            "timestamp": datetime.now().isoformat(),
            "nodes": node_analysis,
            "pods": pod_analysis,
            "services": svc_analysis,
            "deployments": deploy_analysis,
            "resources": pod_resources,
            "events": event_analysis,
            "security": security_summary,
        }
        print(json.dumps(result, indent=2))

    elif args.output == "prometheus":
        exporter = PrometheusExporter()
        exporter.update_metrics(nodes, pods, services, deployments, security_summary, pod_resources)
        print(exporter.generate_output())


if __name__ == "__main__":
    main()
