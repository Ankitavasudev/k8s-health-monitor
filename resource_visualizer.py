#!/usr/bin/env python3
"""Resource usage visualizer for Kubernetes clusters."""

import json
import sys
from typing import List, Dict
from dataclasses import dataclass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    print("[!] pip install rich"); sys.exit(1)

console = Console()


@dataclass
class ResourceUsage:
    name: str
    cpu_request: str
    cpu_limit: str
    memory_request: str
    memory_limit: str
    cpu_actual: str = "N/A"
    memory_actual: str = "N/A"


def parse_cpu(cpu_str: str) -> int:
    """Parse CPU string to millicores."""
    if not cpu_str or cpu_str == "N/A":
        return 0
    cpu_str = str(cpu_str)
    if "m" in cpu_str:
        return int(cpu_str.replace("m", ""))
    try:
        return int(float(cpu_str) * 1000)
    except:
        return 0


def parse_memory(mem_str: str) -> int:
    """Parse memory string to MiB."""
    if not mem_str or mem_str == "N/A":
        return 0
    mem_str = str(mem_str)
    if "Gi" in mem_str:
        return int(float(mem_str.replace("Gi", "")) * 1024)
    if "Mi" in mem_str:
        return int(mem_str.replace("Mi", ""))
    if "Ki" in mem_str:
        return int(float(mem_str.replace("Ki", "")) / 1024)
    try:
        return int(mem_str)
    except:
        return 0


def cpu_bar(used: int, total: int, width: int = 20) -> str:
    if total == 0:
        return "[dim]N/A[/dim]"
    pct = min(used / total * 100, 100)
    filled = int(pct / 100 * width)
    color = "green" if pct < 60 else "yellow" if pct < 80 else "red"
    return f"[{color}]{'█' * filled}{'░' * (width - filled)}[/] {pct:.0f}%"


def memory_bar(used: int, total: int, width: int = 20) -> str:
    if total == 0:
        return "[dim]N/A[/dim]"
    pct = min(used / total * 100, 100)
    filled = int(pct / 100 * width)
    color = "green" if pct < 60 else "yellow" if pct < 80 else "red"
    return f"[{color}]{'█' * filled}{'░' * (width - filled)}[/] {pct:.0f}%"


def visualize_resources(resources: List[ResourceUsage]):
    table = Table(title="Resource Usage Visualization", box=box.ROUNDED, show_lines=True)
    table.add_column("Container", style="cyan", no_wrap=True)
    table.add_column("CPU", min_width=25)
    table.add_column("Memory", min_width=25)

    for r in resources:
        cpu_req = parse_cpu(r.cpu_request)
        cpu_lim = parse_cpu(r.cpu_limit)
        mem_req = parse_memory(r.memory_request)
        mem_lim = parse_memory(r.memory_limit)

        cpu_display = f"{r.cpu_request}/{r.cpu_limit}"
        mem_display = f"{r.memory_request}/{r.memory_limit}"

        table.add_row(
            r.name,
            f"{cpu_display}\n{cpu_bar(cpu_req, cpu_lim)}",
            f"{mem_display}\n{memory_bar(mem_req, mem_lim)}"
        )

    console.print(table)

    total_cpu_req = sum(parse_cpu(r.cpu_request) for r in resources)
    total_cpu_lim = sum(parse_cpu(r.cpu_limit) for r in resources)
    total_mem_req = sum(parse_memory(r.memory_request) for r in resources)
    total_mem_lim = sum(parse_memory(r.memory_limit) for r in resources)

    summary = Table(box=box.SIMPLE, show_header=False)
    summary.add_column("Metric", style="bold")
    summary.add_column("Value")
    summary.add_row("Total CPU Requests", f"{total_cpu_req}m / {total_cpu_lim}m")
    summary.add_row("Total Memory Requests", f"{total_mem_req}Mi / {total_mem_lim}Mi")
    summary.add_row("CPU Utilization", f"{total_cpu_req/total_cpu_lim*100:.1f}%" if total_cpu_lim > 0 else "N/A")
    summary.add_row("Memory Utilization", f"{total_mem_req/total_mem_lim*100:.1f}%" if total_mem_lim > 0 else "N/A")
    console.print(Panel(summary, title="Cluster Resource Summary", border_style="cyan"))


if __name__ == "__main__":
    demo = [
        ResourceUsage("nginx-1", "100m", "500m", "128Mi", "256Mi"),
        ResourceUsage("nginx-2", "100m", "500m", "128Mi", "256Mi"),
        ResourceUsage("redis-0", "250m", "1000m", "512Mi", "1Gi"),
        ResourceUsage("postgres-0", "500m", "2000m", "1Gi", "4Gi"),
        ResourceUsage("app-backend", "200m", "800m", "256Mi", "512Mi"),
        ResourceUsage("app-frontend", "50m", "200m", "64Mi", "128Mi"),
        ResourceUsage("worker-1", "300m", "1000m", "256Mi", "1Gi"),
    ]
    visualize_resources(demo)