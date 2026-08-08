#!/usr/bin/env python3
"""K8s Health Monitor v3.0 - Advanced Kubernetes Cluster Health Checker with Security Scanning"""

import subprocess, json, sys, os, time, argparse
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    print("[!] pip install rich"); sys.exit(1)

console = Console()

@dataclass
class SecurityIssue:
    resource: str; namespace: str; severity: str; rule: str; message: str; remediation: str

@dataclass
class PVCInfo:
    name: str; namespace: str; status: str; capacity: str; storage_class: str; bound: bool

@dataclass
class ResourceQuota:
    namespace: str; cpu_used: str; cpu_limit: str; memory_used: str; memory_limit: str; pods_used: int; pods_limit: int; usage_pct: float

@dataclass
class NetworkPolicy:
    name: str; namespace: str; ingress_rules: int; egress_rules: int

class KubectlClient:
    def __init__(self, kubeconfig=None, context=None, namespace=""):
        self.kubeconfig, self.context, self.namespace = kubeconfig, context, namespace

    def _cmd(self, args):
        cmd = ["kubectl"]
        if self.kubeconfig: cmd.extend(["--kubeconfig", self.kubeconfig])
        if self.context: cmd.extend(["--context", self.context])
        if self.namespace: cmd.extend(["-n", self.namespace])
        cmd.extend(args); return cmd

    def run(self, args, json_out=True, timeout=30):
        cmd = self._cmd(args)
        if json_out: cmd.append("-o"); cmd.append("json")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0: return None
            return json.loads(r.stdout) if json_out else {"output": r.stdout}
        except: return None

    def available(self): return self.run(["version", "--client"], json_out=False) is not None
    def get(self, resource, ns=""):
        args = ["get", resource]
        if ns: args.extend(["-n", ns])
        else: args.extend(["--all-namespaces"])
        d = self.run(args); return d.get("items", []) if d else []
    def get_nodes(self): return self.get("nodes")
    def get_pods(self, ns=""): return self.get("pods", ns)
    def get_deployments(self, ns=""): return self.get("deployments", ns)
    def get_services(self, ns=""): return self.get("services", ns)
    def get_events(self, ns=""): return self.get("events", ns)
    def get_pvcs(self, ns=""): return self.get("pvc", ns)
    def get_pvs(self): return self.get("pv")
    def get_quotas(self, ns=""): return self.get("resourcequotas", ns)
    def get_netpol(self, ns=""): return self.get("networkpolicies", ns)
    def get_clusterroles(self): return self.get("clusterroles")
    def get_service_accounts(self, ns=""): return self.get("serviceaccounts", ns)
    def get_namespaces(self): return self.get("namespaces")
    def get_ingresses(self, ns=""): return self.get("ingresses", ns)


class SecurityScanner:
    def __init__(self, client: KubectlClient):
        self.client = client; self.issues = []

    def scan(self):
        pods = self.client.get_pods()
        for pod in pods:
            ns = pod.get("metadata", {}).get("namespace", "default")
            name = pod["metadata"]["name"]
            for c in pod.get("spec", {}).get("containers", []):
                sc = c.get("securityContext", {})
                if sc.get("privileged"):
                    self._add(ns, name, "CRITICAL", "SEC001", f"Container '{c['name']}' runs PRIVILEGED", "Remove privileged: true")
                if sc.get("runAsUser") == 0:
                    self._add(ns, name, "CRITICAL", "SEC002", f"Container '{c['name']}' runs as ROOT", "Set runAsUser to non-zero")
                if not sc.get("readOnlyRootFilesystem"):
                    self._add(ns, name, "WARNING", "SEC003", f"Container '{c['name']}' has writable rootfs", "Set readOnlyRootFilesystem: true")
                if not sc.get("allowPrivilegeEscalation") == False:
                    self._add(ns, name, "WARNING", "SEC004", f"Container '{c['name']}' allows privilege escalation", "Set allowPrivilegeEscalation: false")

        crs = self.client.get_clusterroles()
        for cr in crs:
            name = cr["metadata"]["name"]
            for rule in cr.get("rules", []):
                if "*" in (rule.get("resources") or []):
                    self._add("cluster", name, "CRITICAL", "RBAC001", f"ClusterRole '{name}' has wildcard resources", "Apply least privilege")
                if "*" in (rule.get("verbs") or []):
                    self._add("cluster", name, "WARNING", "RBAC002", f"ClusterRole '{name}' has wildcard verbs", "Restrict to specific verbs")

        sa = self.client.get_service_accounts()
        for s in sa:
            ns = s.get("metadata", {}).get("namespace", "default")
            name = s["metadata"]["name"]
            if s.get("automountServiceAccountToken", True) and name != "default":
                self._add(ns, name, "WARNING", "SA001", f"SA '{name}' auto-mounts token", "Set automountServiceAccountToken: false")

        ns_data = self.client.get_namespaces()
        netpol = self.client.get_netpol()
        np_ns = set(p.get("metadata", {}).get("namespace") for p in netpol)
        for ns in ns_data:
            n = ns["metadata"]["name"]
            if n.startswith("kube-"): continue
            if n not in np_ns:
                self._add(n, "namespace", "WARNING", "NET001", f"Namespace '{n}' has no NetworkPolicy", "Add default-deny policy")
        return self.issues

    def _add(self, ns, res, sev, rule, msg, fix):
        self.issues.append(SecurityIssue(res, ns, sev, rule, msg, fix))


class ResourceAnalyzer:
    def __init__(self, client: KubectlClient): self.client = client

    def analyze_pvcs(self):
        pvcs = self.client.get_pvcs()
        return [PVCInfo(p["metadata"]["name"], p.get("metadata",{}).get("namespace","default"),
                p.get("status",{}).get("phase","Unknown"), str(p.get("status",{}).get("capacity",{}).get("storage","N/A")),
                p.get("spec",{}).get("storageClassName","N/A"), p.get("status",{}).get("phase") == "Bound") for p in pvcs]

    def analyze_quotas(self):
        quotas = self.client.get_quotas()
        results = []
        for q in quotas:
            ns = q.get("metadata",{}).get("namespace","default")
            h = q.get("status",{}).get("hard",{}); u = q.get("status",{}).get("used",{})
            try: pct = int(u.get("cpu","0").replace("m","")) / max(int(h.get("cpu","0").replace("m","")),1) * 100
            except: pct = 0
            results.append(ResourceQuota(ns, u.get("cpu","0"), h.get("cpu","0"), u.get("memory","0"), h.get("memory","0"),
                int(u.get("pods","0")), int(h.get("pods","0")), pct))
        return results

    def analyze_netpol(self):
        policies = self.client.get_netpol()
        return [NetworkPolicy(p["metadata"]["name"], p.get("metadata",{}).get("namespace","default"),
                len(p.get("spec",{}).get("ingress",[])), len(p.get("spec",{}).get("egress",[]))) for p in policies]


class HealthAnalyzer:
    @staticmethod
    def nodes(nodes):
        t = len(nodes)
        r = sum(1 for n in nodes if any(c.get("type")=="Ready" and c.get("status")=="True" for c in n.get("status",{}).get("conditions",[])))
        return {"total":t,"ready":r,"not_ready":t-r,"score":r/t*100 if t else 0,"status":"HEALTHY" if t-r==0 else "WARNING"}

    @staticmethod
    def pods(pods):
        t = len(pods)
        run = sum(1 for p in pods if p.get("status",{}).get("phase")=="Running")
        fail = sum(1 for p in pods if p.get("status",{}).get("phase")=="Failed")
        pend = sum(1 for p in pods if p.get("status",{}).get("phase")=="Pending")
        rl = sum(1 for p in pods for cs in p.get("status",{}).get("containerStatuses",[]) if cs.get("restartCount",0)>5)
        return {"total":t,"running":run,"failed":fail,"pending":pend,"restart_loops":rl,"score":run/t*100 if t else 0,"status":"HEALTHY" if fail==0 else "CRITICAL"}

    @staticmethod
    def deployments(deps):
        t = len(deps)
        h = sum(1 for d in deps if d.get("status",{}).get("readyReplicas",0)==d.get("status",{}).get("replicas",0))
        return {"total":t,"healthy":h,"degraded":t-h,"score":h/t*100 if t else 0,"status":"HEALTHY" if t-h==0 else "WARNING"}


class Recommender:
    def generate(self, sec, quotas, pvcs, node_a, pod_a):
        r = []
        crit = sum(1 for i in sec if i.severity=="CRITICAL")
        warn = sum(1 for i in sec if i.severity=="WARNING")
        if crit: r.append(f"CRITICAL: {crit} security issues — fix privileged containers & RBAC immediately")
        if warn: r.append(f"WARNING: {warn} security warnings — review network policies & service accounts")
        for q in quotas:
            if q.usage_pct > 80: r.append(f"Namespace '{q.namespace}' CPU at {q.usage_pct:.0f}% — increase limits")
        unbound = [p for p in pvcs if not p.bound]
        if unbound: r.append(f"{len(unbound)} unbound PVCs — check storage provisioner")
        if node_a["not_ready"]>0: r.append(f"{node_a['not_ready']} nodes not ready — check kubelet")
        if pod_a["restart_loops"]>0: r.append(f"{pod_a['restart_loops']} pods in restart loop — check resource limits")
        if not r: r.append("Cluster healthy. No action needed.")
        return r


class Display:
    @staticmethod
    def banner(): console.print(Panel.fit("[bold cyan]K8s Health Monitor v3.0.0[/bold cyan]\n[dim]Security + PVC + RBAC + Quotas + Recommendations[/dim]", border_style="cyan"))
    @staticmethod
    def bar(s):
        f = int(s/10); c = "green" if s>=80 else "yellow" if s>=50 else "red"
        return f"[{c}]{'|'*f}[/{c}][dim]{'.'*(10-f)}[/dim] {s:.0f}%"
    @staticmethod
    def security(issues):
        if not issues: console.print("[green]No security issues[/green]"); return
        t = Table(title="Security Analysis", box=box.ROUNDED, show_lines=True)
        t.add_column("Sev",width=10); t.add_column("Rule",width=8); t.add_column("Resource",style="cyan"); t.add_column("Issue",max_width=50); t.add_column("Fix",max_width=40,style="dim")
        for i in issues:
            sc = {"CRITICAL":"red","WARNING":"yellow","INFO":"blue"}.get(i.severity,"white")
            t.add_row(f"[{sc}]{i.severity}[/{sc}]",i.rule,i.resource,i.message,i.remediation)
        console.print(t)
    @staticmethod
    def pvcs(pvcs):
        if not pvcs: console.print("[dim]No PVCs found[/dim]"); return
        t = Table(title="Persistent Volume Claims", box=box.ROUNDED)
        t.add_column("Namespace",style="cyan"); t.add_column("Name"); t.add_column("Status"); t.add_column("Capacity",justify="right"); t.add_column("StorageClass",style="dim"); t.add_column("Bound")
        for p in pvcs:
            bc = "green" if p.bound else "red"; sc2 = "green" if p.status=="Bound" else "yellow"
            t.add_row(p.namespace,p.name,f"[{sc2}]{p.status}[/{sc2}]",p.capacity,p.storage_class,f"[{bc}]{'Yes' if p.bound else 'No'}[/{bc}]")
        console.print(t)
    @staticmethod
    def quotas(quotas):
        if not quotas: console.print("[dim]No quotas[/dim]"); return
        t = Table(title="Resource Quotas", box=box.ROUNDED)
        t.add_column("Namespace",style="cyan"); t.add_column("CPU"); t.add_column("Memory"); t.add_column("Pods"); t.add_column("Usage")
        for q in quotas:
            uc = "green" if q.usage_pct<60 else "yellow" if q.usage_pct<80 else "red"
            t.add_row(q.namespace,f"{q.cpu_used}/{q.cpu_limit}",f"{q.memory_used}/{q.memory_limit}",f"{q.pods_used}/{q.pods_limit}",f"[{uc}]{q.usage_pct:.0f}%[/{uc}]")
        console.print(t)
    @staticmethod
    def netpol(pols):
        if not pols: console.print("[dim]No network policies[/dim]"); return
        t = Table(title="Network Policies", box=box.ROUNDED)
        t.add_column("Namespace",style="cyan"); t.add_column("Name"); t.add_column("Ingress",justify="center"); t.add_column("Egress",justify="center")
        for p in pols: t.add_row(p.namespace,p.name,str(p.ingress_rules),str(p.egress_rules))
        console.print(t)
    @staticmethod
    def recs(r): console.print(Panel("\n".join(f"[yellow]*[/yellow] {x}" for x in r),title="[bold]Recommendations[/bold]",border_style="yellow"))


def demo_data():
    nodes = [{"metadata":{"name":"master-01","labels":{"node-role.kubernetes.io/master":""},"creationTimestamp":"2026-01-15T10:00:00Z"},"status":{"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"kubeletVersion":"v1.30.2"}}},
             {"metadata":{"name":"worker-01","labels":{"node-role.kubernetes.io/worker":""},"creationTimestamp":"2026-02-20T14:30:00Z"},"status":{"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"kubeletVersion":"v1.30.2"}}},
             {"metadata":{"name":"worker-02","labels":{"node-role.kubernetes.io/worker":""},"creationTimestamp":"2026-03-10T09:15:00Z"},"status":{"conditions":[{"type":"Ready","status":"False"}],"nodeInfo":{"kubeletVersion":"v1.30.2"}}}]
    pods = [{"metadata":{"name":"nginx-1","namespace":"default","creationTimestamp":"2026-07-01T08:00:00Z"},"status":{"phase":"Running","containerStatuses":[{"restartCount":0}]},"spec":{"nodeName":"worker-01","containers":[{"name":"nginx","securityContext":{"privileged":False,"readOnlyRootFilesystem":True,"runAsUser":1000}}]}},
            {"metadata":{"name":"redis-0","namespace":"default","creationTimestamp":"2026-07-15T12:00:00Z"},"status":{"phase":"Running","containerStatuses":[{"restartCount":2}]},"spec":{"nodeName":"worker-01","containers":[{"name":"redis","securityContext":{"privileged":False,"readOnlyRootFilesystem":False,"runAsUser":0}}]}},
            {"metadata":{"name":"debug-pod","namespace":"kube-system","creationTimestamp":"2026-08-01T10:00:00Z"},"status":{"phase":"Running","containerStatuses":[{"restartCount":0}]},"spec":{"nodeName":"master-01","containers":[{"name":"debug","securityContext":{"privileged":True,"runAsUser":0}}]}},
            {"metadata":{"name":"failed-job","namespace":"batch","creationTimestamp":"2026-08-05T22:00:00Z"},"status":{"phase":"Failed","containerStatuses":[{"restartCount":10}]},"spec":{"nodeName":"worker-02","containers":[{"name":"job","securityContext":{}}]}}]
    deps = [{"metadata":{"name":"nginx","namespace":"default","creationTimestamp":"2026-07-01T08:00:00Z"},"status":{"replicas":3,"readyReplicas":3}},
            {"metadata":{"name":"redis","namespace":"default","creationTimestamp":"2026-07-15T12:00:00Z"},"status":{"replicas":2,"readyReplicas":1}}]
    return nodes, pods, deps


def cmd_check(args):
    Display.banner()
    client = KubectlClient(args.kubeconfig, args.context, args.namespace)
    live = client.available()
    if live: console.print("[green]Live cluster data[/green]\n")
    else: console.print("[yellow]DEMO mode[/yellow]\n"); client = KubectlClient()

    sec = SecurityScanner(client).scan()
    ra = ResourceAnalyzer(client)
    pvcs = ra.analyze_pvcs(); quotas = ra.analyze_quotas(); netpol = ra.analyze_netpol()

    ha = HealthAnalyzer()
    nodes_data = client.get_nodes() if live else demo_data()[0]
    pods_data = client.get_pods() if live else demo_data()[1]
    deps_data = client.get_deployments() if live else demo_data()[2]

    na = ha.nodes(nodes_data); pa = ha.pods(pods_data); da = ha.deployments(deps_data)
    avg = (na["score"]+pa["score"]+da["score"])/3

    Display.security(sec); console.print()
    Display.pvcs(pvcs); console.print()
    Display.quotas(quotas); console.print()
    Display.netpol(netpol); console.print()

    s = Table(box=box.SIMPLE, show_header=False)
    s.add_column("K",style="bold"); s.add_column("V",justify="right")
    s.add_row("Nodes",f"{na['ready']}/{na['total']}"); s.add_row("Pods",f"{pa['running']}/{pa['total']}")
    s.add_row("Failed",str(pa["failed"])); s.add_row("Deployments",f"{da['healthy']}/{da['total']}")
    s.add_row("Security",f"[red]{sum(1 for i in sec if i.severity=='CRITICAL')}[/red] crit, [yellow]{sum(1 for i in sec if i.severity=='WARNING')}[/yellow] warn")
    s.add_row("Score",Display.bar(avg))
    console.print(Panel(s,title="[bold]Summary[/bold]",border_style="cyan"))

    recs = Recommender().generate(sec, quotas, pvcs, na, pa)
    Display.recs(recs)

    if args.output:
        with open(args.output,"w") as f:
            json.dump({"timestamp":datetime.now().isoformat(),"score":avg,"security":[asdict(i) for i in sec],"pvcs":[asdict(p) for p in pvcs],"quotas":[asdict(q) for q in quotas],"recommendations":recs},f,indent=2,default=str)
        console.print(f"\n[green]Exported to {args.output}[/green]")


def cmd_ns(args):
    client = KubectlClient(args.kubeconfig, args.context)
    data = client.get_namespaces()
    if not data: console.print("[red]No namespaces[/red]"); return
    t = Table(title="Namespaces",box=box.ROUNDED); t.add_column("Name",style="cyan"); t.add_column("Status",style="green")
    for ns in data: t.add_row(ns["metadata"]["name"],ns.get("status",{}).get("phase","Unknown"))
    console.print(t)


def main():
    p = argparse.ArgumentParser(description="K8s Health Monitor v3.0.0")
    p.add_argument("--kubeconfig"); p.add_argument("--context")
    sub = p.add_subparsers(dest="cmd")
    cp = sub.add_parser("check"); cp.add_argument("-n","--namespace",default=""); cp.add_argument("-o","--output"); cp.set_defaults(func=cmd_check)
    sub.add_parser("namespaces").set_defaults(func=cmd_ns)
    args = p.parse_args()
    if not args.command: cmd_check(args)
    else: args.func(args)

if __name__ == "__main__": main()
