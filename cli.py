#!/usr/bin/env python3
"""CLI wrapper for K8s Health Monitor."""

import argparse
import sys
from k8s_monitor import K8sMonitor
from namespace_compare import compare_namespaces, export_json, export_html
from resource_visualizer import visualize_resources

def main():
    parser = argparse.ArgumentParser(description="K8s Health Monitor - Analyze Kubernetes cluster health")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Run health monitor")
    monitor_parser.add_argument("--output", "-o", help="Output file (JSON)")
    monitor_parser.add_argument("--format", choices=["json", "html", "text"], default="text", help="Output format")

    # Compare command
    compare_parser = subparsers.add_parser("compare", help="Compare namespaces")
    compare_parser.add_argument("--output", "-o", help="Output file (JSON/HTML)")
    compare_parser.add_argument("--format", choices=["json", "html", "text"], default="text", help="Output format")

    # Visualize command
    viz_parser = subparsers.add_parser("visualize", help="Visualize resource usage")
    viz_parser.add_argument("--output", "-o", help="Output file (JSON)")

    # Version
    subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command == "monitor":
        monitor = K8sMonitor()
        results = monitor.analyze()
        if args.output:
            if args.format == "json":
                import json
                with open(args.output, "w") as f:
                    json.dump(results, f, indent=2)
            elif args.format == "html":
                export_html(results, args.output)
            else:
                print(results)
        else:
            print(results)

    elif args.command == "compare":
        print("Namespace comparison requires live cluster connection")
        print("Use: kubectl get pods --all-namespaces")

    elif args.command == "visualize":
        print("Resource visualization requires live cluster connection")
        print("Use: kubectl top nodes")

    elif args.command == "version":
        print("K8s Health Monitor v3.0.0")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()