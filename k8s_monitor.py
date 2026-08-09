#!/usr/bin/env python3
"""K8s Health Monitor v3.0 - Advanced Kubernetes Cluster Health Checker with Security Scanning"""

import subprocess
import json
import sys
import argparse
from dataclasses import dataclass, asdict

try:
    from rich.console import Console
except ImportError:
    print("[!] pip install rich")
    sys.exit(1)

console = Console()


@dataclass
class SecurityIssue:
    resource: str
    namespace: str
    severity: str
    rule: str
    message: str
    remediation: str


@dataclass
class PVCInfo:
    name: str
    namespace: str
    status: str
    capacity: str
    storage_class: str
    bound: bool


@dataclass
class ResourceQuota:
    namespace: str
    cpu_used: str
    cpu_limit: str
    memory_used: str
    memory_limit: str
    pods_used: int
    pods_limit: int
    usage_pct: float


@dataclass
class NetworkPolicy:
    name: str
    namespace: str
    ingress_rules: int
    egress_rules: int


class KubectlClient:
    def __init__(self, kubeconfig=None, context=None, namespace=""):
        self.kubeconfig = kubeconfig
        self.context = context
        self.namespace = namespace

    def _cmd(self, args):
        cmd = ["kubectl"]
        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])
        if self.context:
            cmd.extend(["--context", self.context])
        if self.namespace:
            cmd.extend(["-n", self.namespace])
        cmd.extend(args)
        return cmd

    def run(self, args, json_out=True, timeout=30):
        cmd = self._cmd(args)
        if json_out:
            cmd.append("-o")
            cmd.append("json")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0:
                return None
            return json.loads(r.stdout) if json_out else {"output": r.stdout}
        except Exception:
            return None

    def available(self):
        return self.run(["version", "--client"], json_out=False) is not None

    def get(self, resource, ns=""):
        args = ["get", resource]
        if ns:
            args.extend(["-n", ns])
        else:
            args.extend(["--all-namespaces"])
        d = self.run(args)
        return d.get("items", []) if d else []

    def get_nodes(self):
        return self.get("nodes")

    def get_pods(self, ns=""):
        return self.get("pods", ns)

    def get_deployments(self, ns=""):
        return self.get("deployments", ns)

    def get_services(self, ns=""):
        return self.get("services", ns)

    def get_events(self, ns=""):
        return self.get("events", ns)

    def get_pvcs(self, ns=""):
        return self.get("pvc", ns)

    def get_pvs(self):
        return self.get("pv")

    def get_quotas(self, ns=""):
        return self.get("resourcequotas", ns)

    def get_netpol(self, ns=""):
        return self.get("networkpolicies", ns)

    def get_clusterroles(self):
        return self.get("clusterroles")

    def get_service_accounts(self, ns=""):
        return self.get("serviceaccounts", ns)

    def get_namespaces(self):
        return self.get("namespaces")

    def get_ingresses(self, ns=""):
        return self.get("ingresses", ns)


class SecurityScanner:
    def __init__(self, client):
        self.client = client
        self.issues = []

    def _add(self, ns, name, severity, rule, message, remediation):
        self.issues.append(SecurityIssue(
            resource=name,
            namespace=ns,
            severity=severity,
            rule=rule,
            message=message,
            remediation=remediation
        ))

    def scan(self):
        pods = self.client.get_pods()
        for pod in pods:
            ns = pod.get("metadata", {}).get("namespace", "default")
            name = pod["metadata"]["name"]
            for c in pod.get("spec", {}).get("containers", []):
                sc = c.get("securityContext", {})
                if sc.get("privileged"):
                    self._add(ns, name, "CRITICAL", "SEC001",
                              f"Container '{c['name']}' runs PRIVILEGED",
                              "Remove privileged: true")
                if sc.get("runAsUser") == 0:
                    self._add(ns, name, "CRITICAL", "SEC002",
                              f"Container '{c['name']}' runs as ROOT",
                              "Set runAsUser to non-zero")
                if not sc.get("readOnlyRootFilesystem"):
                    self._add(ns, name, "WARNING", "SEC003",
                              f"Container '{c['name']}' has writable rootfs",
                              "Set readOnlyRootFilesystem: true")
                if not sc.get("allowPrivilegeEscalation") == False:
                    self._add(ns, name, "WARNING", "SEC004",
                              f"Container '{c['name']}' allows privilege escalation",
                              "Set allowPrivilegeEscalation: false")
        return self.issues


class ResourceAnalyzer:
    def __init__(self, client):
        self.client = client

    def analyze_nodes(self):
        nodes = self.client.get_nodes()
        results = []
        for node in nodes:
            name = node["metadata"]["name"]
            status = "Ready" if any(
                c["type"] == "Ready" and c["status"] == "True"
                for c in node.get("status", {}).get("conditions", [])
            ) else "NotReady"
            results.append({"name": name, "status": status})
        return results


class HealthAnalyzer:
    def __init__(self, client):
        self.client = client

    def analyze(self):
        pods = self.client.get_pods()
        results = {"total": len(pods), "running": 0, "pending": 0, "failed": 0}
        for pod in pods:
            phase = pod.get("status", {}).get("phase", "Unknown")
            if phase == "Running":
                results["running"] += 1
            elif phase == "Pending":
                results["pending"] += 1
            elif phase == "Failed":
                results["failed"] += 1
        return results


class Recommender:
    def __init__(self, security_issues, resource_analysis, health_analysis):
        self.security_issues = security_issues
        self.resource_analysis = resource_analysis
        self.health_analysis = health_analysis

    def get_recommendations(self):
        recs = []
        critical = [i for i in self.security_issues if i.severity == "CRITICAL"]
        if critical:
            recs.append(f"Address {len(critical)} critical security issues immediately")
        unhealthy = self.health_analysis.get("failed", 0)
        if unhealthy > 0:
            recs.append(f"Investigate {unhealthy} failed pods")
        return recs


class K8sMonitor:
    def __init__(self, kubeconfig=None, context=None, namespace=""):
        self.client = KubectlClient(kubeconfig, context, namespace)

    def analyze(self):
        console.print("[bold cyan]Running K8s Health Monitor v3.0...[/bold cyan]")

        scanner = SecurityScanner(self.client)
        security_issues = scanner.scan()

        resource_analyzer = ResourceAnalyzer(self.client)
        resource_analysis = resource_analyzer.analyze_nodes()

        health_analyzer = HealthAnalyzer(self.client)
        health_analysis = health_analyzer.analyze()

        recommender = Recommender(security_issues, resource_analysis, health_analysis)
        recommendations = recommender.get_recommendations()

        return {
            "security_issues": [asdict(i) for i in security_issues],
            "resource_analysis": resource_analysis,
            "health_analysis": health_analysis,
            "recommendations": recommendations
        }


def main():
    parser = argparse.ArgumentParser(description="K8s Health Monitor v3.0")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--context", help="Kubernetes context")
    parser.add_argument("--namespace", "-n", help="Namespace")
    parser.add_argument("--output", "-o", help="Output file")
    args = parser.parse_args()

    monitor = K8sMonitor(args.kubeconfig, args.context, args.namespace)
    results = monitor.analyze()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]Results saved to {args.output}[/green]")
    else:
        console.print_json(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()