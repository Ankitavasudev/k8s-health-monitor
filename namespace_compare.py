#!/usr/bin/env python3
"""Namespace comparison tool for Kubernetes clusters."""

import json
import sys
from typing import Dict, List, Any
from dataclasses import dataclass, asdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
except ImportError:
    print("[!] pip install rich"); sys.exit(1)

console = Console()


@dataclass
class NamespaceStats:
    name: str
    pods: int = 0
    services: int = 0
    deployments: int = 0
    configmaps: int = 0
    secrets: int = 0
    pvcs: int = 0
    network_policies: int = 0
    resource_quotas: int = 0
    cpu_usage: str = "N/A"
    memory_usage: str = "N/A"


def compare_namespaces(namespaces: List[NamespaceStats]) -> Dict[str, Any]:
    if not namespaces:
        return {"error": "No namespaces to compare"}

    stats = {
        "total_namespaces": len(namespaces),
        "most_pods": max(namespaces, key=lambda x: x.pods),
        "most_services": max(namespaces, key=lambda x: x.services),
        "most_deployments": max(namespaces, key=lambda x: x.deployments),
        "largest_total": max(namespaces, key=lambda x: x.pods + x.services + x.deployments),
        "without_quotas": [n for n in namespaces if n.resource_quotas == 0],
        "without_netpol": [n for n in namespaces if n.network_policies == 0],
    }
    return stats


def display_comparison(namespaces: List[NamespaceStats]):
    table = Table(title="Namespace Comparison", box=box.ROUNDED, show_lines=True)
    table.add_column("Namespace", style="cyan", no_wrap=True)
    table.add_column("Pods", justify="right")
    table.add_column("Services", justify="right")
    table.add_column("Deployments", justify="right")
    table.add_column("PVCs", justify="right")
    table.add_column("NetPol", justify="center")
    table.add_column("Quotas", justify="center")

    for ns in sorted(namespaces, key=lambda x: x.pods, reverse=True):
        netpol = "[green]Yes[/green]" if ns.network_policies > 0 else "[red]No[/red]"
        quotas = "[green]Yes[/green]" if ns.resource_quotas > 0 else "[red]No[/red]"
        table.add_row(
            ns.name, str(ns.pods), str(ns.services), str(ns.deployments),
            str(ns.pvcs), netpol, quotas
        )

    console.print(table)

    stats = compare_namespaces(namespaces)
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total namespaces: {stats['total_namespaces']}")
    console.print(f"  Most pods: {stats['most_pods'].name} ({stats['most_pods'].pods})")
    console.print(f"  Without quotas: {len(stats['without_quotas'])}")
    console.print(f"  Without network policies: {len(stats['without_netpol'])}")


def export_json(namespaces: List[NamespaceStats], filepath: str):
    data = {
        "namespaces": [asdict(n) for n in namespaces],
        "comparison": compare_namespaces(namespaces)
    }
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    console.print(f"[green]Exported to {filepath}[/green]")


def export_html(namespaces: List[NamespaceStats], filepath: str):
    rows = ""
    for ns in sorted(namespaces, key=lambda x: x.pods, reverse=True):
        netpol_class = "yes" if ns.network_policies > 0 else "no"
        quota_class = "yes" if ns.resource_quotas > 0 else "no"
        rows += f"""
        <tr>
            <td>{ns.name}</td>
            <td>{ns.pods}</td>
            <td>{ns.services}</td>
            <td>{ns.deployments}</td>
            <td>{ns.pvcs}</td>
            <td class="{netpol_class}">{'Yes' if ns.network_policies > 0 else 'No'}</td>
            <td class="{quota_class}">{'Yes' if ns.resource_quotas > 0 else 'No'}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Namespace Comparison</title>
    <style>
        body {{ font-family: system-ui; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; }}
        .yes {{ color: green; font-weight: bold; }}
        .no {{ color: red; font-weight: bold; }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <h1>Kubernetes Namespace Comparison</h1>
    <table>
        <tr><th>Namespace</th><th>Pods</th><th>Services</th><th>Deployments</th><th>PVCs</th><th>NetPol</th><th>Quotas</th></tr>
        {rows}
    </table>
</body>
</html>"""

    with open(filepath, "w") as f:
        f.write(html)
    console.print(f"[green]HTML report exported to {filepath}[/green]")


if __name__ == "__main__":
    demo = [
        NamespaceStats("default", pods=12, services=5, deployments=3, pvcs=2, network_policies=1, resource_quotas=1),
        NamespaceStats("kube-system", pods=8, services=4, deployments=2, pvcs=0, network_policies=0, resource_quotas=0),
        NamespaceStats("production", pods=25, services=10, deployments=8, pvcs=5, network_policies=3, resource_quotas=2),
        NamespaceStats("staging", pods=15, services=7, deployments=5, pvcs=3, network_policies=1, resource_quotas=1),
    ]
    display_comparison(demo)