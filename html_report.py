#!/usr/bin/env python3
"""Self-contained HTML report renderer for k8s-health-monitor.

The output is one file: no CDN, no fonts, no scripts, no network requests.
Open it from disk, email it, or publish it as a static page.

Author: Ankita Salaria | GitHub: https://github.com/Ankitavasudev
"""

from html import escape
from typing import Any, Dict, List

VERSION = "1.1.0"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
STATUS_CLASS = {
    "HEALTHY": "ok",
    "WARNING": "warn",
    "CRITICAL": "bad",
    "UNKNOWN": "unknown",
}

CSS = """
:root {
  color-scheme: dark;
  --bg: #0d1117;
  --panel: #161b22;
  --panel-2: #1c2128;
  --line: #30363d;
  --fg: #e6edf3;
  --muted: #8b949e;
  --ok: #3fb950;
  --warn: #d29922;
  --bad: #f85149;
  --unknown: #8b949e;
  --accent: #58a6ff;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 32px 20px 64px;
  background: var(--bg);
  color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 1080px; margin: 0 auto; }
header { border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 28px; }
h1 { font-size: 24px; margin: 0 0 6px; letter-spacing: -0.01em; }
h1 .dot { color: var(--accent); }
.meta { color: var(--muted); font-size: 13px; font-family: var(--mono); }
h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.08em;
     color: var(--muted); margin: 40px 0 14px; font-weight: 600; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; }
.card {
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 16px 18px; border-left-width: 3px;
}
.card.ok { border-left-color: var(--ok); }
.card.warn { border-left-color: var(--warn); }
.card.bad { border-left-color: var(--bad); }
.card.unknown { border-left-color: var(--unknown); }
.card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
.card .value { font-size: 26px; font-weight: 600; font-family: var(--mono); margin: 4px 0 2px; }
.card .status { font-size: 12px; font-family: var(--mono); }
.ok .status { color: var(--ok); }
.warn .status { color: var(--warn); }
.bad .status { color: var(--bad); }
.unknown .status { color: var(--unknown); }
.card .detail { color: var(--muted); font-size: 12px; margin-top: 6px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
caption { text-align: left; color: var(--muted); font-size: 12px; padding-bottom: 8px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
tbody tr:hover { background: var(--panel-2); }
td.num, th.num { text-align: right; font-family: var(--mono); }
code, .mono { font-family: var(--mono); font-size: 12px; }
.chip {
  display: inline-block; padding: 1px 8px; border-radius: 999px;
  font-size: 11px; font-family: var(--mono); border: 1px solid currentColor;
}
.chip.CRITICAL, .chip.bad { color: var(--bad); }
.chip.HIGH { color: #ff8f6b; }
.chip.MEDIUM { color: var(--warn); }
.chip.LOW { color: var(--muted); }
.chip.ok { color: var(--ok); }
.scroll { overflow-x: auto; }
.empty { color: var(--muted); font-size: 13px; padding: 12px 0; }
.bars { display: grid; gap: 8px; }
.bar-row { display: grid; grid-template-columns: 90px 1fr 64px; align-items: center; gap: 10px; font-size: 13px; }
.bar { height: 8px; border-radius: 4px; background: var(--panel-2); overflow: hidden; }
.bar > i { display: block; height: 100%; background: var(--accent); }
footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line);
         color: var(--muted); font-size: 12px; font-family: var(--mono); }
footer a { color: var(--accent); text-decoration: underline; text-underline-offset: 2px; }
@media (max-width: 640px) {
  body { padding: 20px 14px 40px; }
  .bar-row { grid-template-columns: 70px 1fr 52px; }
}
@media print {
  :root { color-scheme: light; --bg: #fff; --panel: #fff; --panel-2: #f6f8fa;
          --fg: #1f2328; --muted: #57606a; --line: #d0d7de; }
  body { padding: 0; }
  tbody tr:hover { background: transparent; }
}
/* --- interactivity (pure CSS, no scripts) --- */
.bar > i { animation: grow 1.1s cubic-bezier(.2,.7,.2,1); transform-origin: left; }
@keyframes grow { from { transform: scaleX(0); } to { transform: scaleX(1); } }
.card { transition: transform .18s ease, border-color .18s ease; }
.card:hover { transform: translateY(-3px); border-color: var(--accent); }
details.section { margin: 0; }
details.section > summary {
  list-style: none; cursor: pointer; display: flex; align-items: center; gap: 10px;
  user-select: none; margin: 40px 0 14px;
}
details.section > summary::before {
  content: "▸"; color: var(--accent); font-size: 12px; transition: transform .2s ease;
  display: inline-block;
}
details.section[open] > summary::before { transform: rotate(90deg); }
details.section > summary h2 { margin: 0; }
details.section > summary::-webkit-details-marker { display: none; }
.findings { margin: 0; }
.findings > input { position: absolute; opacity: 0; pointer-events: none; }
.findings > label {
  cursor: pointer; display: inline-block; padding: 3px 10px; border-radius: 999px;
  font-size: 11px; border: 1px solid var(--line); color: var(--muted);
  font-family: var(--mono); margin: 0 6px 8px 0;
  transition: color .15s, border-color .15s, background .15s;
}
.findings > label:hover { color: var(--fg); }
.findings > input:checked + label { color: var(--accent); border-color: var(--accent); background: rgba(88,166,255,.12); }
.sev-all:checked ~ .scroll tr[data-sev],
.sev-critical:checked ~ .scroll tr[data-sev]:not([data-sev="CRITICAL"]),
.sev-high:checked ~ .scroll tr[data-sev]:not([data-sev="HIGH"]),
.sev-medium:checked ~ .scroll tr[data-sev]:not([data-sev="MEDIUM"]),
.sev-low:checked ~ .scroll tr[data-sev]:not([data-sev="LOW"]) { display: none; }
"""



def _num(value: Any) -> str:
    if isinstance(value, float):
        if value == int(value):
            return str(int(value))
        return "%.2f" % value
    return str(value)


def _status_card(label: str, value: Any, status: str, detail: str = "") -> str:
    css = STATUS_CLASS.get(status, "unknown")
    return (
        '<div class="card %s">'
        '<div class="label">%s</div>'
        '<div class="value">%s</div>'
        '<div class="status">%s</div>%s'
        "</div>" % (
            css, escape(label), escape(_num(value)), escape(status),
            '<div class="detail">%s</div>' % escape(detail) if detail else "",
        )
    )


def _table(caption: str, headers: List[str], rows: List[List[str]],
           numeric: List[int] = None, empty: str = "Nothing to report.") -> str:
    numeric = numeric or []
    if not rows:
        return '<p class="empty">%s</p>' % escape(empty)
    head = "".join(
        '<th scope="col"%s>%s</th>' % (' class="num"' if i in numeric else "", escape(h))
        for i, h in enumerate(headers)
    )
    body = "".join(
        "<tr>%s</tr>" % "".join(
            "<td%s>%s</td>" % (' class="num"' if i in numeric else "", cell)
            for i, cell in enumerate(row)
        )
        for row in rows
    )
    return (
        '<div class="scroll"><table><caption>%s</caption>'
        "<thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>"
        % (escape(caption), head, body)
    )


def _bar(label: str, value: float, maximum: float, text: str) -> str:
    pct = 0 if not maximum else max(0.0, min(100.0, value / maximum * 100))
    return (
        '<div class="bar-row"><span>%s</span>'
        '<span class="bar" role="img" aria-label="%s of %s"><i style="width:%.1f%%"></i></span>'
        '<span class="mono">%s</span></div>'
        % (escape(label), escape(_num(value)), escape(_num(maximum)), pct, escape(text))
    )


def _resource_section(report: Dict[str, Any]) -> str:
    pods = report.get("resources", {}) or {}
    nodes = report.get("node_resources", {}) or {}
    if not pods and not nodes:
        return ""
    total = pods.get("total_containers", 0) or 0
    limited = pods.get("containers_with_limits", 0) or 0
    requested = pods.get("containers_with_requests", 0) or 0
    parts = ['<div class="bars">']
    parts.append(_bar("limits", limited, total, "%d/%d" % (limited, total)))
    parts.append(_bar("requests", requested, total, "%d/%d" % (requested, total)))
    parts.append(_bar(
        "unbounded", pods.get("unbounded_containers", 0) or 0, total,
        "%d of %d" % (pods.get("unbounded_containers", 0) or 0, total),
    ))
    parts.append("</div>")

    rows = []
    if nodes:
        rows.append([
            "cluster capacity", escape(_num(nodes.get("cpu_capacity", 0))) + " CPU",
            escape(_num(nodes.get("memory_capacity", 0) / 1024 ** 3)) + " GiB",
            escape(_num(nodes.get("pods_capacity", 0))) + " pods",
        ])
    rows.append([
        "requested by pods", escape(_num(pods.get("total_cpu_requests", 0))) + " CPU",
        escape(_num(pods.get("total_mem_requests", 0) / 1024 ** 3)) + " GiB", "-",
    ])
    rows.append([
        "limited by pods", escape(_num(pods.get("total_cpu_limits", 0))) + " CPU",
        escape(_num(pods.get("total_mem_limits", 0) / 1024 ** 3)) + " GiB", "-",
    ])
    parts.append(_table(
        "What the cluster has versus what workloads reserve",
        ["Scope", "CPU", "Memory", "Pod slots"], rows, numeric=[1, 2, 3],
    ))
    return "".join(parts)


def _security_section(report: Dict[str, Any]) -> str:
    summary = report.get("security", {}) or {}
    findings = report.get("findings", []) or []
    if not any(summary.values()) and not findings:
        return '<p class="empty">Security scan disabled for this run.</p>'

    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f.get("severity", "LOW"))
                       if f.get("severity") in SEVERITY_ORDER else 99),
    )

    # Radio inputs double as severity filter chips (pure CSS, no scripts).
    # The .scroll table is a sibling of the radios; ~ selectors toggle rows.
    radios = ['<input type="radio" class="sev-all" id="sev-all" name="sev" checked>'
              '<label for="sev-all">ALL</label>']
    for sev in SEVERITY_ORDER:
        n = summary.get(sev, 0) or 0
        if n:
            radios.append(
                '<input type="radio" class="sev-%s" id="sev-%s" name="sev">'
                '<label for="sev-%s">%s %d</label>' % (sev.lower(), sev.lower(), sev.lower(), sev, n)
            )

    rows = []
    for f in ordered[:60]:
        sev = f.get("severity", "LOW")
        rows.append([
            '<tr data-sev="%s">' % escape(sev),
            '<span class="chip %s">%s</span>' % (escape(sev), escape(sev)),
            "<code>%s</code>" % escape(f.get("rule", "")),
            escape(f.get("resource", "")),
            escape(f.get("container", "-") or "-"),
            escape(f.get("message", "")),
            "</tr>",
        ])
    head = (
        '<thead><tr><th scope="col">Severity</th><th scope="col">Rule</th>'
        '<th scope="col">Resource</th><th scope="col">Container</th>'
        '<th scope="col">What is wrong</th></tr></thead>'
    )
    body_rows = []
    for r in rows:
        body_rows.append(
            r[0] + "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
            (r[1], r[2], r[3], r[4], r[5])
        )
    table = (
        '<div class="scroll"><table><caption>Findings, worst first (showing %d of %d)</caption>'
        '%s<tbody>%s</tbody></table></div>'
        % (len(rows), len(findings), head, "".join(body_rows))
    )
    if not findings:
        table = '<p class="empty">No findings — every scanned resource passed.</p>'
    return '<div class="findings">%s%s</div>' % ("".join(radios), table)


def _events_section(report: Dict[str, Any]) -> str:
    events = report.get("events", {}) or {}
    rows = []
    for w in events.get("warning_details", []) or []:
        rows.append([
            "<code>%s</code>" % escape(w.get("reason", "")),
            escape(w.get("object", "")),
            escape(w.get("message", "")),
        ])
    return _table(
        "%d warning event(s) in the last hour" % (events.get("warnings", 0) or 0),
        ["Reason", "Object", "Message"], rows,
        empty="No warning events.",
    )


def _pods_section(report: Dict[str, Any]) -> str:
    rows = []
    for pod in (report.get("pod_details") or [])[:80]:
        phase = pod.get("phase", "Unknown")
        cls = {"Running": "ok", "Failed": "bad", "Pending": "MEDIUM"}.get(phase, "")
        restarts = pod.get("restarts", 0) or 0
        restarts_cell = escape(_num(restarts))
        if restarts > 5:
            restarts_cell = '<span class="chip bad">%s</span>' % restarts_cell
        rows.append([
            escape(pod.get("namespace", "")),
            "<code>%s</code>" % escape(pod.get("name", "")),
            '<span class="chip %s">%s</span>' % (cls, escape(phase)),
            restarts_cell,
        ])
    return _table(
        "Workloads as reported by the API server",
        ["Namespace", "Pod", "Phase", "Restarts"], rows, numeric=[3],
        empty="No pods returned.",
    )


def render_html(report: Dict[str, Any], mode: str = "live",
                context: str = "", version: str = VERSION) -> str:
    """Render a complete standalone HTML document for one scan."""
    nodes = report.get("nodes", {}) or {}
    pods = report.get("pods", {}) or {}
    services = report.get("services", {}) or {}
    deployments = report.get("deployments", {}) or {}
    timestamp = report.get("timestamp", "")

    pod_detail = "%d running · %d pending · %d failed · %d restart loops" % (
        pods.get("running", 0) or 0, pods.get("pending", 0) or 0,
        pods.get("failed", 0) or 0, pods.get("restart_loops", 0) or 0,
    )
    node_detail = "%d of %d ready" % (nodes.get("ready", 0) or 0, nodes.get("total", 0) or 0)
    deploy_detail = "%d degraded of %d" % (
        deployments.get("degraded", 0) or 0, deployments.get("total", 0) or 0)
    svc_detail = "%d service(s)" % (services.get("total", 0) or 0)

    cards = "".join([
        _status_card("Nodes", nodes.get("total", 0), nodes.get("status", "UNKNOWN"), node_detail),
        _status_card("Pods", pods.get("total", 0), pods.get("status", "UNKNOWN"), pod_detail),
        _status_card("Deployments", deployments.get("total", 0),
                     deployments.get("status", "UNKNOWN"), deploy_detail),
        _status_card("Services", services.get("total", 0),
                     services.get("status", "UNKNOWN"), svc_detail),
    ])

    seen = [
        '<span>generated %s</span>' % escape(timestamp),
        "<span>source: %s</span>" % escape(mode),
    ]
    if context:
        seen.insert(0, "<span>context: %s</span>" % escape(context))
    seen.append("<span>v%s</span>" % escape(version))
    meta = ' <span aria-hidden="true">·</span> '.join(seen)

    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<meta name="description" content="Kubernetes cluster health report: node, pod and deployment status, resource accounting and security findings.">
<style>%s</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>Kubernetes Health Report<span class="dot">.</span></h1>
  <p class="meta">%s</p>
</header>
<main>
<details class="section" open>
  <summary><h2 id="summary">Summary</h2></summary>
  <div class="cards">%s</div>
</details>
<details class="section" open>
  <summary><h2 id="resources">Resource accounting</h2></summary>
  %s
</details>
<details class="section" open>
  <summary><h2 id="security">Security scan</h2></summary>
  %s
</details>
<details class="section" open>
  <summary><h2 id="events">Warning events</h2></summary>
  %s
</details>
<details class="section">
  <summary><h2 id="pods">Pods</h2></summary>
  %s
</details>
</main>
<footer>
  Generated by <a href="https://github.com/Ankitavasudev/k8s-health-monitor">k8s-health-monitor</a>
  v%s — one file, no scripts, no network requests.
</footer>
</div>
</body>
</html>
""" % (
        escape("Kubernetes Health Report" + (" — " + context if context else "")),
        CSS,
        meta,
        cards,
        _resource_section(report),
        _security_section(report),
        _events_section(report),
        _pods_section(report),
        escape(version),
    )
