#!/usr/bin/env python3
"""
Читает .flows файл mitmproxy (protobuf) и создаёт подробный HTML-отчёт.
Выделяет ошибки, таймауты, failed-запросы, 5xx, connection errors.
Включает графики: время ответа, распределение статусов, топ хостов, таймлайн.

Использование:
    python export.py capture_20260629_120000.flows
    python export.py capture_20260629_120000.flows -o report.html
    python export.py *.flows              # объединит все файлы
"""

import os
import sys
import html as html_mod
import gzip
import argparse
import base64
import warnings
import math
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from collections import Counter, defaultdict

warnings.filterwarnings("ignore", category=DeprecationWarning)

from mitmproxy.io import FlowReader


ERROR_TIMEOUT = 3.0
ERROR_SLOW = 1.0


def read_flows(path):
    flows = []
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rb") as f:
        reader = FlowReader(f)
        for flow in reader.stream():
            flows.append(flow)
    return flows


def flow_to_dict(flow):
    d = {}
    d["type"] = flow.type

    if flow.request:
        req = flow.request
        try:
            req_body_text = req.get_text(strict=False) if req.content else ""
        except Exception:
            req_body_text = req.raw_content.decode("utf-8", errors="replace") if req.content else ""
        d["request"] = {
            "method": req.method,
            "url": req.pretty_url,
            "headers": list(req.headers.items()),
            "body": req_body_text,
            "content_type": req.headers.get("content-type", ""),
        }
    else:
        d["request"] = {"method": "?", "url": "", "headers": [], "body": "", "content_type": ""}

    d["response"] = None
    if flow.response:
        resp = flow.response
        d["response"] = {
            "status_code": resp.status_code,
            "headers": list(resp.headers.items()),
            "body": safe_get_text(resp),
            "content_type": resp.headers.get("content-type", ""),
            "size": len(safe_get_body_b64(resp)),
        }

    d["error"] = None
    if flow.error:
        d["error"] = {
            "msg": flow.error.msg,
            "timestamp": flow.error.timestamp,
        }

    d["timestamp_start"] = flow.request.timestamp_start or 0
    d["timestamp_end"] = flow.request.timestamp_end or 0
    ts_start = flow.request.timestamp_start or 0
    ts_end = flow.request.timestamp_end or 0
    d["duration"] = (ts_end - ts_start) if ts_start and ts_end else 0

    return d


def safe_get_text(resp):
    try:
        return resp.get_text(strict=False)
    except Exception:
        pass
    try:
        raw = resp.raw_content
        if raw:
            return raw.decode("utf-8", errors="replace")
    except Exception:
        pass
    return ""


def safe_get_body_b64(resp):
    try:
        return resp.raw_content or b""
    except Exception:
        return b""


def classify_flow(fd):
    severity = "ok"
    tags = []
    issues = []

    error = fd.get("error")
    resp = fd.get("response")
    duration = fd.get("duration", 0)

    status = resp["status_code"] if resp else 0

    if error:
        severity = "error"
        tags.append("error")
        err_msg = error.get("msg", "")
        issues.append(f"Connection error: {err_msg}")

        msg_lower = err_msg.lower()
        if "timeout" in msg_lower:
            tags.append("timeout")
            issues[-1] = f"CONNECTION TIMEOUT — сервер не отвечает ({err_msg})"
        elif "refused" in msg_lower:
            tags.append("refused")
            issues[-1] = f"CONNECTION REFUSED — сервис не запущен ({err_msg})"
        elif "reset" in msg_lower:
            tags.append("reset")
            issues[-1] = f"CONNECTION RESET — сервер разорвал соединение ({err_msg})"
        elif "ssl" in msg_lower or "tls" in msg_lower:
            tags.append("ssl")
            issues[-1] = f"SSL/TLS ERROR — проблема с сертификатом ({err_msg})"
        elif "dns" in msg_lower or "resolve" in msg_lower:
            tags.append("dns")
            issues[-1] = f"DNS ERROR — не удаётся разрешить имя ({err_msg})"
        elif "eof" in msg_lower:
            tags.append("eof")
            issues[-1] = f"UNEXPECTED EOF — соединение закрыто ({err_msg})"

    elif status >= 500:
        severity = "error"
        tags.append("5xx")
        issues.append(f"Server Error: HTTP {status}")

    elif status == 0:
        severity = "error"
        tags.append("no-response")
        issues.append("Нет ответа — запрос не получил HTTP-ответ")

    elif 400 <= status < 500:
        severity = "warn"
        tags.append("4xx")
        issues.append(f"Client Error: HTTP {status}")

    elif 300 <= status < 400:
        tags.append("3xx")

    if duration > ERROR_TIMEOUT:
        severity = "error"
        tags.append("timeout")
        issues.append(f"Very slow: {duration:.1f}s (>{ERROR_TIMEOUT}s)")
    elif duration > ERROR_SLOW:
        if severity == "ok":
            severity = "warn"
        tags.append("slow")
        issues.append(f"Slow: {duration:.1f}s")

    return severity, tags, issues


def format_size(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def status_color(code):
    if code < 300:
        return "#2e7d32"
    if code < 400:
        return "#f57f17"
    if code < 500:
        return "#e65100"
    return "#c62828"


def escape(text):
    return html_mod.escape(str(text)) if text else ""


def flow_to_html(fd, idx):
    severity, tags, issues = classify_flow(fd)

    req = fd.get("request", {})
    resp = fd.get("response")
    error = fd.get("error")

    method = req.get("method", "?")
    url = req.get("url", "")
    req_headers = req.get("headers", [])
    req_body = req.get("body", "")

    status = resp["status_code"] if resp else 0
    resp_headers = resp["headers"] if resp else []
    resp_body = resp["body"] if resp else ""
    resp_size = resp["size"] if resp else 0

    timestamp = fd.get("timestamp_start", 0)
    try:
        ts_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts_str = str(timestamp)

    duration = fd.get("duration", 0)
    duration_str = f"{duration:.3f}s" if duration else "-"

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path_str = parsed.path or "/"
    if parsed.query:
        path_str += "?" + parsed.query

    card_class = "flow-card"
    if severity == "error":
        card_class += " card-error"
    elif severity == "warn":
        card_class += " card-warn"

    badges = ""
    for tag in tags:
        is_err = tag in ("error", "timeout", "refused", "reset", "ssl", "dns", "no-response", "5xx", "eof")
        is_warn = tag in ("4xx", "slow")
        badge_class = "badge-error" if is_err else "badge-warn" if is_warn else "badge-info"
        labels = {
            "error": "ERROR", "timeout": "TIMEOUT", "refused": "REFUSED",
            "reset": "RESET", "ssl": "SSL", "dns": "DNS", "no-response": "NO RESP",
            "5xx": "5xx", "4xx": "4xx", "slow": "SLOW", "3xx": "3xx",
            "tcp": "TCP", "ws": "WS", "eof": "EOF",
        }
        label = labels.get(tag, tag.upper())
        badges += f'<span class="{badge_class}">{label}</span>'

    issues_html = ""
    if issues:
        items = "".join(f"<li>{escape(i)}</li>" for i in issues)
        issues_html = f'<div class="issues"><strong>Проблемы:</strong><ul>{items}</ul></div>'

    error_block = ""
    if error:
        error_block = f"""
        <div class="section error-section">
          <h3>Connection Error</h3>
          <div class="error-detail">
            <span class="error-msg">{escape(error.get('msg', ''))}</span>
          </div>
        </div>"""

    method_colors = {
        "GET": "#2e7d32", "POST": "#1565c0", "PUT": "#f57f17",
        "DELETE": "#c62828", "PATCH": "#6a1b9a", "OPTIONS": "#546e7a",
    }
    method_color = method_colors.get(method, "#546e7a")

    req_headers_html = "".join(
        f'<tr><td>{escape(k)}</td><td>{escape(v)}</td></tr>'
        for k, v in req_headers
    )
    resp_headers_html = "".join(
        f'<tr><td>{escape(k)}</td><td>{escape(v)}</td></tr>'
        for k, v in resp_headers
    )

    duration_class = "duration-slow" if duration > ERROR_TIMEOUT else "duration-warn" if duration > ERROR_SLOW else "duration"

    req_body_block = ""
    if req_body:
        truncated = req_body[:10000]
        req_body_block = f"<h4>Body</h4><pre class='body'>{escape(truncated)}</pre>"

    resp_body_block = ""
    if resp_body:
        truncated = resp_body[:10000]
        resp_body_block = f"<h4>Body</h4><pre class='body'>{escape(truncated)}</pre>"

    status_display = status if status else "---"

    return f"""
    <div class="{card_class}" data-tags="{','.join(tags)}" data-severity="{severity}">
      <div class="flow-header" onclick="this.parentElement.classList.toggle('expanded')">
        <div class="flow-main">
          <span class="idx">#{idx}</span>
          <span class="method" style="background:{method_color}">{escape(method)}</span>
          <span class="status" style="color:{status_color(status)}">{status_display}</span>
          <span class="host">{escape(host)}</span>
          <span class="path">{escape(path_str[:120])}</span>
          {badges}
          <span class="{duration_class}">{duration_str}</span>
          <span class="size">{format_size(resp_size)}</span>
          <span class="timestamp">{ts_str}</span>
        </div>
      </div>
      <div class="flow-details">
        {issues_html}
        {error_block}
        <div class="section">
          <h3>Request</h3>
          <div class="url-full">{escape(method)} {escape(url)}</div>
          <h4>Headers</h4>
          <table class="headers">{req_headers_html}</table>
          {req_body_block}
        </div>
        <div class="section">
          <h3>Response</h3>
          <div class="status-line">HTTP/1.1 {status}</div>
          <h4>Headers</h4>
          <table class="headers">{resp_headers_html}</table>
          {resp_body_block}
        </div>
      </div>
    </div>"""


def build_charts(flows_dicts):
    """Строит все графики и возвращает HTML секцию."""
    durations = []
    statuses = Counter()
    hosts = Counter()
    methods = Counter()
    host_durations = defaultdict(list)
    timeline = []

    for fd in flows_dicts:
        d = fd.get("duration", 0)
        if d > 0:
            durations.append(d)

        s = fd.get("response", {}).get("status_code", 0) if fd.get("response") else 0
        statuses[s] += 1

        url = fd.get("request", {}).get("url", "")
        parsed = urlparse(url)
        h = parsed.hostname or "unknown"
        hosts[h] += 1

        m = fd.get("request", {}).get("method", "?")
        methods[m] += 1

        if d > 0:
            host_durations[h].append(d)

        ts = fd.get("timestamp_start", 0)
        if ts > 0:
            timeline.append((ts, d, s, h))

    charts = []

    # --- Chart 1: Response time histogram ---
    if durations:
        buckets = [0, 0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 999]
        labels = ["<100ms", "100-250ms", "250-500ms", "0.5-1s", "1-2s", "2-3s", "3-5s", "5-10s", ">10s"]
        counts = [0] * len(labels)
        for d in durations:
            for i in range(len(buckets) - 1):
                if buckets[i] <= d < buckets[i + 1]:
                    counts[i] += 1
                    break

        max_count = max(counts) if counts else 1
        bars = ""
        for i, (label, count) in enumerate(zip(labels, counts)):
            w = (count / max_count * 100) if max_count > 0 else 0
            color = "#f85149" if i >= 6 else "#d29922" if i >= 4 else "#2e7d32"
            bars += f'<div class="chart-bar-row"><span class="chart-label">{label}</span><div class="chart-bar" style="width:{w}%;background:{color}"></div><span class="chart-val">{count}</span></div>'

        p50 = sorted(durations)[len(durations) // 2] if durations else 0
        p95 = sorted(durations)[int(len(durations) * 0.95)] if durations else 0
        p99 = sorted(durations)[int(len(durations) * 0.99)] if durations else 0

        charts.append(f"""
        <div class="chart-card">
          <h3>Время ответа (распределение)</h3>
          <div class="chart-stats">
            <span>P50: <strong>{p50*1000:.0f}ms</strong></span>
            <span>P95: <strong>{p95*1000:.0f}ms</strong></span>
            <span>P99: <strong>{p99*1000:.0f}ms</strong></span>
            <span>Среднее: <strong>{(sum(durations)/len(durations))*1000:.0f}ms</strong></span>
          </div>
          <div class="chart-bars">{bars}</div>
        </div>""")

    # --- Chart 2: Status distribution (donut) ---
    if statuses:
        status_groups = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "Error": 0}
        for s, c in statuses.items():
            if 200 <= s < 300:
                status_groups["2xx"] += c
            elif 300 <= s < 400:
                status_groups["3xx"] += c
            elif 400 <= s < 500:
                status_groups["4xx"] += c
            elif s >= 500:
                status_groups["5xx"] += c
            else:
                status_groups["Error"] += c

        total_s = sum(status_groups.values())
        colors_map = {"2xx": "#2e7d32", "3xx": "#f57f17", "4xx": "#e65100", "5xx": "#c62828", "Error": "#555"}
        legend_items = ""
        segments = ""
        offset = 0
        for group, count in status_groups.items():
            if count == 0:
                continue
            pct = count / total_s * 100
            color = colors_map[group]
            legend_items += f'<div class="legend-item"><span class="legend-color" style="background:{color}"></span>{group}: {count} ({pct:.1f}%)</div>'
            segments += f'<circle r="40" cx="50" cy="50" fill="none" stroke="{color}" stroke-width="14" stroke-dasharray="{pct*2.513} {251.3-pct*2.513}" stroke-dashoffset="-{offset*2.513}" transform="rotate(-90 50 50)"/>'
            offset += pct

        charts.append(f"""
        <div class="chart-card">
          <h3>Распределение статусов</h3>
          <div class="chart-donut-wrap">
            <svg viewBox="0 0 100 100" class="chart-donut">
              <circle r="40" cx="50" cy="50" fill="none" stroke="#21262d" stroke-width="14"/>
              {segments}
              <text x="50" y="50" text-anchor="middle" dy="0.1em" fill="#c9d1d9" font-size="10" font-weight="700">{total_s}</text>
              <text x="50" y="56" text-anchor="middle" dy="0.1em" fill="#8b949e" font-size="5">запросов</text>
            </svg>
            <div class="chart-legend">{legend_items}</div>
          </div>
        </div>""")

    # --- Chart 3: Top hosts ---
    top_hosts = hosts.most_common(10)
    if top_hosts:
        max_h = top_hosts[0][1]
        bars = ""
        for h, c in top_hosts:
            w = c / max_h * 100
            avg_d = sum(host_durations[h]) / len(host_durations[h]) if h in host_durations and host_durations[h] else 0
            avg_str = f"{avg_d*1000:.0f}ms" if avg_d > 0 else "-"
            bars += f'<div class="chart-bar-row"><span class="chart-label chart-host">{escape(h[:30])}</span><div class="chart-bar" style="width:{w}%;background:#1565c0"></div><span class="chart-val">{c} ({avg_str})</span></div>'

        charts.append(f"""
        <div class="chart-card">
          <h3>Топ-10 хостов (количество запросов / среднее время)</h3>
          <div class="chart-bars">{bars}</div>
        </div>""")

    # --- Chart 4: Request timeline ---
    if timeline and len(timeline) > 1:
        t_min = timeline[0][0]
        t_max = timeline[-1][0]
        t_range = t_max - t_min if t_max > t_min else 1
        dots = ""
        for ts, dur, status, host in timeline:
            x = ((ts - t_min) / t_range * 96) + 2
            y = min(dur * 10, 90) if dur > 0 else 5
            color = "#f85149" if status >= 500 else "#e65100" if status >= 400 else "#f57f17" if status >= 300 else "#2e7d32"
            dots += f'<circle cx="{x}" cy="{100-y}" r="2" fill="{color}" opacity="0.7"><title>{escape(host)} {dur*1000:.0f}ms HTTP {status}</title></circle>'
            if dur > 3:
                dots += f'<line x1="{x}" y1="{100-y}" x2="{x}" y2="100" stroke="{color}" stroke-width="0.5" opacity="0.3"/>'

        charts.append(f"""
        <div class="chart-card">
          <h3>Таймлайн запросов (точка = запрос, высота = время ответа)</h3>
          <div class="chart-timeline">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" class="chart-svg-timeline">
              <line x1="2" y1="90" x2="98" y2="90" stroke="#30363d" stroke-width="0.3"/>
              <line x1="2" y1="50" x2="98" y2="50" stroke="#30363d" stroke-width="0.3" stroke-dasharray="1,1"/>
              <line x1="2" y1="10" x2="98" y2="10" stroke="#30363d" stroke-width="0.3" stroke-dasharray="1,1"/>
              <text x="0" y="92" fill="#8b949e" font-size="3">0ms</text>
              <text x="0" y="52" fill="#8b949e" font-size="3">3s</text>
              <text x="0" y="12" fill="#8b949e" font-size="3">9s</text>
              {dots}
            </svg>
          </div>
        </div>""")

    # --- Chart 5: Methods ---
    if methods:
        items = ""
        for m, c in methods.most_common():
            items += f'<span class="method-pill" style="background:{method_colors_dict.get(m, "#546e7a")}">{m}: {c}</span>'
        charts.append(f"""
        <div class="chart-card">
          <h3>HTTP методы</h3>
          <div class="chart-pills">{items}</div>
        </div>""")

    return "\n".join(charts) if charts else ""


method_colors_dict = {
    "GET": "#2e7d32", "POST": "#1565c0", "PUT": "#f57f17",
    "DELETE": "#c62828", "PATCH": "#6a1b9a", "OPTIONS": "#546e7a",
}


def generate_html(flows_dicts, title="mitmproxy Traffic Report"):
    issues_summary = []
    total_errors = 0
    total_timeouts = 0
    total_refused = 0
    total_5xx = 0
    total_slow = 0
    total_tcp_err = 0

    for fd in flows_dicts:
        sev, tags, iss = classify_flow(fd)
        if sev == "error":
            total_errors += 1
        if "timeout" in tags:
            total_timeouts += 1
        if "refused" in tags:
            total_refused += 1
        if "5xx" in tags:
            total_5xx += 1
        if "slow" in tags:
            total_slow += 1
        if "tcp" in tags and "error" in tags:
            total_tcp_err += 1
        if iss:
            url = fd.get("request", {}).get("url", "?")
            issues_summary.append((sev, tags, url, iss))

    cards = "\n".join(flow_to_html(fd, i + 1) for i, fd in enumerate(flows_dicts))

    total = len(flows_dicts)
    methods = {}
    statuses = {}
    total_resp_size = 0
    hosts = set()

    for fd in flows_dicts:
        m = fd.get("request", {}).get("method", "?")
        s = fd.get("response", {}).get("status_code", 0) if fd.get("response") else 0
        methods[m] = methods.get(m, 0) + 1
        statuses[str(s)] = statuses.get(str(s), 0) + 1
        total_resp_size += fd.get("response", {}).get("size", 0) if fd.get("response") else 0
        h = urlparse(fd.get("request", {}).get("url", "")).hostname
        if h:
            hosts.add(h)

    methods_str = ", ".join(f"{k}: {v}" for k, v in sorted(methods.items(), key=lambda x: -x[1]))
    statuses_str = ", ".join(f"{k}: {v}" for k, v in sorted(statuses.items()))

    charts_html = build_charts(flows_dicts)

    issues_section = ""
    if issues_summary:
        rows = ""
        for sev, tags, url, iss in issues_summary:
            color = "#c62828" if sev == "error" else "#f57f17"
            badge = "ERROR" if sev == "error" else "WARN"
            tags_html = " ".join(
                f'<span class="badge-small badge-{"error" if sev == "error" else "warn"}">{t.upper()}</span>'
                for t in tags
            )
            issues_text = "<br>".join(escape(i) for i in iss)
            parsed = urlparse(url)
            short_url = f"{parsed.hostname or ''}{(parsed.path or '/')[:60]}"
            rows += f"""<tr style="border-bottom:1px solid #21262d">
              <td style="color:{color};font-weight:700">{badge}</td>
              <td>{tags_html}</td>
              <td style="color:#58a6ff">{escape(short_url)}</td>
              <td style="color:#f85149">{issues_text}</td>
            </tr>"""
        issues_section = f"""
  <div class="issues-block">
    <h2>Проблемы ({total_errors} ошибок, {total_timeouts} таймаутов, {total_refused} refused, {total_5xx} 5xx, {total_slow} медленных)</h2>
    <table class="issues-table">
      <thead><tr><th>Тип</th><th>Теги</th><th>URL</th><th>Детали</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""
    else:
        issues_section = '<div class="issues-block issues-ok"><h2>Проблем не обнаружено</h2></div>'

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
  h1 {{ color: #58a6ff; margin-bottom: 20px; }}
  h2 {{ color: #f0f6fc; margin-bottom: 12px; font-size: 16px; }}
  h3 {{ color: #58a6ff; margin-bottom: 8px; font-size: 14px; }}
  .stats {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; display: flex; gap: 30px; flex-wrap: wrap; }}
  .stat {{ }}
  .stat-label {{ color: #8b949e; font-size: 12px; text-transform: uppercase; }}
  .stat-value {{ color: #f0f6fc; font-size: 18px; font-weight: 600; }}
  .stat-value.stat-error {{ color: #f85149; }}
  .stat-value.stat-warn {{ color: #d29922; }}
  .stat-value.stat-ok {{ color: #3fb950; }}

  .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 16px; margin-bottom: 20px; }}
  .chart-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }}
  .chart-card h3 {{ margin-bottom: 12px; }}
  .chart-stats {{ display: flex; gap: 20px; margin-bottom: 12px; font-size: 13px; color: #8b949e; }}
  .chart-stats strong {{ color: #c9d1d9; }}
  .chart-bars {{ display: flex; flex-direction: column; gap: 4px; }}
  .chart-bar-row {{ display: flex; align-items: center; gap: 8px; }}
  .chart-label {{ width: 100px; font-size: 11px; color: #8b949e; text-align: right; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .chart-host {{ width: 140px; }}
  .chart-bar {{ height: 16px; border-radius: 3px; min-width: 2px; transition: width 0.3s; }}
  .chart-val {{ font-size: 11px; color: #8b949e; white-space: nowrap; }}
  .chart-donut-wrap {{ display: flex; align-items: center; gap: 20px; }}
  .chart-donut {{ width: 140px; height: 140px; flex-shrink: 0; }}
  .chart-legend {{ display: flex; flex-direction: column; gap: 6px; }}
  .legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 13px; }}
  .legend-color {{ width: 12px; height: 12px; border-radius: 2px; flex-shrink: 0; }}
  .chart-timeline {{ width: 100%; overflow: hidden; }}
  .chart-svg-timeline {{ width: 100%; height: 150px; }}
  .chart-pills {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .method-pill {{ color: #fff; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 700; }}

  .issues-block {{ background: #161b22; border: 1px solid #f85149; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; }}
  .issues-block.issues-ok {{ border-color: #3fb950; }}
  .issues-table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
  .issues-table th {{ text-align: left; padding: 6px 8px; color: #8b949e; border-bottom: 1px solid #30363d; font-size: 11px; text-transform: uppercase; }}
  .issues-table td {{ padding: 6px 8px; vertical-align: top; }}

  .filter-bar {{ margin-bottom: 16px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
  .filter-bar input {{ background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 8px 12px; border-radius: 6px; font-size: 14px; width: 300px; }}
  .filter-bar input:focus {{ outline: none; border-color: #58a6ff; }}
  .filter-btn {{ background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; }}
  .filter-btn:hover {{ border-color: #58a6ff; color: #58a6ff; }}
  .filter-btn.active {{ background: #1f6feb; border-color: #1f6feb; color: #fff; }}
  .filter-btn.btn-error {{ border-color: #f85149; color: #f85149; }}
  .filter-btn.btn-error.active {{ background: #f85149; color: #fff; }}
  .filter-btn.btn-warn {{ border-color: #d29922; color: #d29922; }}
  .filter-btn.btn-warn.active {{ background: #d29922; color: #fff; }}

  .flow-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 8px; overflow: hidden; transition: all 0.2s; }}
  .flow-card:hover {{ border-color: #58a6ff; }}
  .flow-card.card-error {{ border-left: 3px solid #f85149; background: #1a0e0e; }}
  .flow-card.card-error:hover {{ border-color: #f85149; }}
  .flow-card.card-warn {{ border-left: 3px solid #d29922; background: #1a1a0e; }}
  .flow-card.card-warn:hover {{ border-color: #d29922; }}

  .flow-header {{ padding: 12px 16px; cursor: pointer; user-select: none; }}
  .flow-main {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 14px; }}
  .idx {{ color: #484f58; font-size: 12px; min-width: 35px; }}
  .method {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 12px; }}
  .status {{ font-weight: 700; min-width: 30px; }}
  .host {{ color: #58a6ff; font-weight: 600; }}
  .path {{ color: #8b949e; flex: 1; min-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .size {{ color: #8b949e; font-size: 12px; white-space: nowrap; }}
  .duration {{ color: #8b949e; font-size: 12px; white-space: nowrap; }}
  .duration-slow {{ color: #f85149; font-size: 12px; font-weight: 700; white-space: nowrap; }}
  .duration-warn {{ color: #d29922; font-size: 12px; font-weight: 600; white-space: nowrap; }}
  .timestamp {{ color: #484f58; font-size: 12px; white-space: nowrap; }}

  .badge-error {{ background: #f85149; color: #fff; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; }}
  .badge-warn {{ background: #d29922; color: #000; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; }}
  .badge-info {{ background: #30363d; color: #c9d1d9; padding: 1px 6px; border-radius: 3px; font-size: 10px; }}
  .badge-small {{ font-size: 10px; padding: 1px 4px; border-radius: 2px; }}

  .issues {{ background: #1a0e0e; border: 1px solid #f85149; border-radius: 4px; padding: 10px 14px; margin-bottom: 12px; }}
  .issues strong {{ color: #f85149; }}
  .issues ul {{ margin: 4px 0 0 16px; color: #ffa198; font-size: 13px; }}
  .issues li {{ margin-bottom: 2px; }}

  .error-section {{ background: #1a0e0e; border: 1px solid #f85149; border-radius: 4px; padding: 10px 14px; }}
  .error-section h3 {{ color: #f85149; }}
  .error-detail {{ display: flex; gap: 16px; font-size: 13px; }}
  .error-code {{ color: #ffa198; font-weight: 700; }}
  .error-msg {{ color: #f85149; }}

  .flow-details {{ display: none; padding: 16px; border-top: 1px solid #30363d; }}
  .flow-card.expanded .flow-details {{ display: block; }}
  .section {{ margin-bottom: 16px; }}
  .section h3 {{ color: #58a6ff; margin-bottom: 8px; font-size: 14px; }}
  .section h4 {{ color: #8b949e; margin: 8px 0 4px; font-size: 12px; text-transform: uppercase; }}
  .url-full {{ color: #f0f6fc; font-family: monospace; font-size: 13px; word-break: break-all; background: #0d1117; padding: 8px; border-radius: 4px; }}
  .status-line {{ color: #c9d1d9; font-family: monospace; font-size: 13px; }}
  .headers {{ width: 100%; font-size: 13px; border-collapse: collapse; }}
  .headers td {{ padding: 4px 8px; border-bottom: 1px solid #21262d; }}
  .headers td:first-child {{ color: #79c0ff; white-space: nowrap; width: 200px; font-family: monospace; }}
  .headers td:last-child {{ color: #c9d1d9; word-break: break-all; font-family: monospace; }}
  .body {{ background: #0d1117; padding: 12px; border-radius: 4px; font-size: 12px; overflow-x: auto; max-height: 500px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; color: #c9d1d9; font-family: monospace; }}
</style>
</head>
<body>
<div class="container">
  <h1>mitmproxy Traffic Report</h1>
  <div class="stats">
    <div class="stat"><div class="stat-label">Всего запросов</div><div class="stat-value">{total}</div></div>
    <div class="stat"><div class="stat-label">Успешных (2xx)</div><div class="stat-value stat-ok">{total - total_errors}</div></div>
    <div class="stat"><div class="stat-label">Ошибки</div><div class="stat-value {"stat-error" if total_errors else "stat-ok"}">{total_errors}</div></div>
    <div class="stat"><div class="stat-label">Таймауты</div><div class="stat-value {"stat-error" if total_timeouts else "stat-ok"}">{total_timeouts}</div></div>
    <div class="stat"><div class="stat-label">Refused</div><div class="stat-value {"stat-error" if total_refused else "stat-ok"}">{total_refused}</div></div>
    <div class="stat"><div class="stat-label">5xx</div><div class="stat-value {"stat-error" if total_5xx else "stat-ok"}">{total_5xx}</div></div>
    <div class="stat"><div class="stat-label">Медленные</div><div class="stat-value {"stat-warn" if total_slow else "stat-ok"}">{total_slow}</div></div>
    <div class="stat"><div class="stat-label">Хостов</div><div class="stat-value">{len(hosts)}</div></div>
    <div class="stat"><div class="stat-label">Размер</div><div class="stat-value">{format_size(total_resp_size)}</div></div>
  </div>

  <div class="charts-grid">
    {charts_html}
  </div>

  {issues_section}
  <div class="filter-bar">
    <input type="text" id="filter" placeholder="Фильтр: URL, хост, метод..." oninput="filterFlows()">
    <button class="filter-btn active" onclick="setFilter('all', this)">Все ({total})</button>
    <button class="filter-btn btn-error" onclick="setFilter('error', this)">Ошибки ({total_errors})</button>
    <button class="filter-btn btn-warn" onclick="setFilter('slow', this)">Медленные ({total_slow})</button>
    <button class="filter-btn" onclick="setFilter('timeout', this)">Таймауты ({total_timeouts})</button>
    <button class="filter-btn" onclick="setFilter('refused', this)">Refused ({total_refused})</button>
    <button class="filter-btn" onclick="setFilter('5xx', this)">5xx ({total_5xx})</button>
  </div>
  <div id="flows">{cards}</div>
</div>
<script>
let currentFilter = 'all';

function setFilter(tag, btn) {{
  currentFilter = tag;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  filterFlows();
}}

function filterFlows() {{
  const q = document.getElementById('filter').value.toLowerCase();
  document.querySelectorAll('.flow-card').forEach(c => {{
    const tags = c.getAttribute('data-tags') || '';
    const text = c.textContent.toLowerCase();
    const matchText = !q || text.includes(q);
    const matchTag = currentFilter === 'all' || tags.includes(currentFilter);
    c.style.display = (matchText && matchTag) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Экспорт .flows в HTML")
    parser.add_argument("files", nargs="+", help="Файлы .flows для обработки")
    parser.add_argument("-o", "--output", default=None, help="Имя выходного HTML файла")
    args = parser.parse_args()

    all_flows = []
    for f in args.files:
        p = Path(f)
        if not p.exists():
            print(f"[!] Файл не найден: {f}")
            continue
        try:
            flows = read_flows(str(p))
            print(f"[+] {f}: {len(flows)} запросов")
            all_flows.extend(flows)
        except Exception as e:
            print(f"[!] Ошибка чтения {f}: {e}")

    if not all_flows:
        print("[!] Нет данных для экспорта")
        sys.exit(1)

    all_flows.sort(key=lambda x: x.request.timestamp_start or 0)

    flows_dicts = [flow_to_dict(f) for f in all_flows]

    err_count = sum(1 for fd in flows_dicts if classify_flow(fd)[0] == "error")
    warn_count = sum(1 for fd in flows_dicts if classify_flow(fd)[0] == "warn")
    print(f"[*] Найдено: {err_count} ошибок, {warn_count} предупреждений")

    if args.output:
        out_path = args.output
    else:
        out_path = "report.html"

    html_content = generate_html(flows_dicts)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n[*] Готово! {len(flows_dicts)} запросов → {out_path}")
    print(f"[*] Откройте в браузере: file:///{os.path.abspath(out_path)}")


if __name__ == "__main__":
    main()
