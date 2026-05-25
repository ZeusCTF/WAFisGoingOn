"""
app.py — WAFisGoingOn main application
Reverse proxy + WAF with rate limiting, full request inspection,
configurable block responses, and a live dashboard.
"""

import json
import logging
import os
import time
from collections import defaultdict
from functools import wraps
from pathlib import Path

import requests
from flask import Flask, request, jsonify, render_template_string, Response

from waf.config import load as load_config, build_detection_config
from waf.detector import WAFDetector

# ── Bootstrap ────────────────────────────────────────────────────────────────

CFG = load_config(os.environ.get("WAF_CONFIG", "config.yaml"))

log_level = getattr(logging, CFG["logging"]["level"].upper(), logging.INFO)
handlers = [logging.StreamHandler()]
if CFG["logging"].get("file"):
    handlers.append(logging.FileHandler(CFG["logging"]["file"]))
logging.basicConfig(level=log_level, handlers=handlers,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("waf")

DETECTOR = WAFDetector(
    config=build_detection_config(CFG),
    db_path=CFG["logging"]["db"],
)

app = Flask(__name__, template_folder="dashboard/templates",
            static_folder="dashboard/static")

# ── Rate limiter (in-memory, per IP) ─────────────────────────────────────────

_rate_buckets: dict[str, list[float]] = defaultdict(list)
RL_CFG = CFG["rate_limit"]


def _is_rate_limited(ip: str) -> bool:
    if not RL_CFG.get("enabled", True):
        return False
    now = time.time()
    window = 60.0
    rpm = RL_CFG.get("requests_per_minute", 60)
    bucket = _rate_buckets[ip]
    # Evict old timestamps
    _rate_buckets[ip] = [t for t in bucket if now - t < window]
    if len(_rate_buckets[ip]) >= rpm:
        return True
    _rate_buckets[ip].append(now)
    return False


# ── Dashboard auth decorator ──────────────────────────────────────────────────

def _dashboard_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = CFG["dashboard"]["api_key"]
        provided = request.headers.get("X-WAF-Key") or request.args.get("key")
        if provided != key:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# ── Block response ─────────────────────────────────────────────────────────────

BLOCK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Request Blocked</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #0f1117;
    color: #e2e8f0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .card {
    background: #1a1d2e;
    border: 1px solid #2d3048;
    border-radius: 16px;
    padding: 3rem;
    max-width: 480px;
    text-align: center;
  }
  .shield {
    font-size: 56px;
    margin-bottom: 1.5rem;
    display: block;
  }
  h1 { font-size: 1.5rem; font-weight: 600; margin-bottom: 0.75rem; color: #f1f5f9; }
  p  { font-size: 0.9rem; color: #94a3b8; line-height: 1.6; }
  .ref {
    margin-top: 1.5rem;
    font-size: 0.75rem;
    color: #475569;
    font-family: monospace;
  }
  .badge {
    display: inline-block;
    margin-top: 1.5rem;
    font-size: 0.7rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 4px 12px;
    border-radius: 99px;
    background: rgba(239,68,68,0.15);
    color: #f87171;
    border: 1px solid rgba(239,68,68,0.3);
  }
</style>
</head>
<body>
<div class="card">
  <span class="shield">🛡️</span>
  <h1>Request Blocked</h1>
  <p>This request was identified as potentially malicious and has been blocked
     by WAFisGoingOn. The attempt has been logged and recorded.</p>
  <div class="badge">Security Event Recorded</div>
  <p class="ref">Surface: {{ surface }} &nbsp;·&nbsp; Score: {{ score }}</p>
</div>
</body>
</html>"""


def _block_response(surface: str, score: float) -> Response:
    cfg = CFG["block"]
    status = cfg.get("status_code", 403)
    if cfg.get("format") == "json":
        body = cfg.get("json_body", '{"error":"blocked"}')
        return Response(body, status=status, mimetype="application/json")
    html = render_template_string(BLOCK_HTML, surface=surface,
                                  score=f"{score:.3f}")
    return Response(html, status=status, mimetype="text/html")


# ── Proxy helper ──────────────────────────────────────────────────────────────

def _proxy(path: str) -> Response:
    bcfg = CFG["backend"]
    url = f"{bcfg['scheme']}://{bcfg['host']}:{bcfg['port']}/{path}"

    try:
        if request.method == "GET":
            r = requests.get(url, params=request.args,
                             headers={k: v for k, v in request.headers if k != "Host"},
                             timeout=bcfg.get("timeout", 10))
        else:
            r = requests.request(
                method=request.method,
                url=url,
                params=request.args,
                data=request.get_data(),
                headers={k: v for k, v in request.headers if k != "Host"},
                timeout=bcfg.get("timeout", 10),
            )
        return Response(r.content, status=r.status_code,
                        headers={"Server": "WAFisGoingOn/2.0"})
    except requests.exceptions.ConnectionError:
        return Response("Backend unavailable", status=502)
    except requests.exceptions.Timeout:
        return Response("Backend timeout", status=504)


# ── Main proxy route ──────────────────────────────────────────────────────────

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>",            methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path: str):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # Skip WAF for dashboard routes
    dashboard_route = CFG["dashboard"]["route"].lstrip("/")
    if path.startswith(dashboard_route):
        return Response("Not found", 404)

    # Rate limit
    if _is_rate_limited(ip):
        logger.warning(f"Rate limit hit: {ip}")
        return Response("Too many requests", status=429,
                        headers={"Retry-After": "60"})

    # WAF inspection
    blocked, surface, score = DETECTOR.inspect(
        ip=ip,
        method=request.method,
        path="/" + path,
        get_params=request.args.to_dict(),
        post_params=request.form.to_dict(),
        headers=dict(request.headers),
    )

    if blocked:
        logger.warning(f"BLOCKED {ip} {request.method} /{path} [{surface}] score={score:.3f}")
        return _block_response(surface, score)

    return _proxy(path)


# ── Dashboard routes ──────────────────────────────────────────────────────────

DASHBOARD_ROUTE = CFG["dashboard"]["route"]


@app.route(DASHBOARD_ROUTE)
@_dashboard_auth
def dashboard():
    return Response(_DASHBOARD_HTML, mimetype="text/html")


@app.route(DASHBOARD_ROUTE + "/api/stats")
@_dashboard_auth
def dashboard_stats():
    return jsonify(DETECTOR.get_stats())


@app.route(DASHBOARD_ROUTE + "/api/events")
@_dashboard_auth
def dashboard_events():
    stats = DETECTOR.get_stats()
    return jsonify(stats["recent"])


@app.route(DASHBOARD_ROUTE + "/api/report.pdf")
@_dashboard_auth
def dashboard_report():
    """Generate and stream a PDF threat report."""
    try:
        from waf.report import generate
        stats = DETECTOR.get_stats()
        pdf_bytes = generate(stats)
        timestamp = __import__("datetime").datetime.utcnow().strftime("%Y%m%d_%H%M")
        return Response(
            pdf_bytes,
            status=200,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=waf_threat_report_{timestamp}.pdf",
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        logger.exception("PDF generation failed")
        return jsonify({"error": f"Report generation failed: {e}"}), 500


# ── Embedded dashboard HTML ───────────────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAFisGoingOn — Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0f1117; --surface: #1a1d2e; --border: #2d3048;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #6366f1;
    --red: #f87171; --green: #34d399; --yellow: #fbbf24;
  }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: var(--bg); color: var(--text); min-height: 100vh; }
  header {
    display: flex; align-items: center; gap: 12px;
    padding: 1rem 2rem; border-bottom: 1px solid var(--border);
  }
  header h1 { font-size: 1.1rem; font-weight: 600; }
  .header-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
  .live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green);
              animation: pulse 2s infinite; flex-shrink: 0; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .report-btn {
    font-size: 0.78rem; padding: 6px 14px; border-radius: 8px; cursor: pointer;
    background: var(--accent); color: #fff; border: none; font-weight: 500;
    display: flex; align-items: center; gap: 6px; text-decoration: none;
    transition: opacity .15s;
  }
  .report-btn:hover { opacity: .85; }
  .report-btn.loading { opacity: .6; pointer-events: none; }
  main { padding: 2rem; max-width: 1280px; margin: 0 auto; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
             gap: 1rem; margin-bottom: 2rem; }
  .metric {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.25rem;
  }
  .metric-label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase;
                  letter-spacing: 0.06em; margin-bottom: 0.5rem; }
  .metric-value { font-size: 2rem; font-weight: 600; }
  .metric-value.red    { color: var(--red); }
  .metric-value.green  { color: var(--green); }
  .metric-value.yellow { color: var(--yellow); }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem; margin-bottom: 2rem; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2rem; }
  @media (max-width: 900px) { .grid-3,.grid-2 { grid-template-columns: 1fr; } }
  .panel {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.25rem;
  }
  .panel h2 { font-size: 0.85rem; font-weight: 600; color: var(--muted);
              text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 1rem; }
  .chart-wrap { position: relative; height: 220px; }
  .donut-wrap { position: relative; height: 220px; display: flex; align-items: center; justify-content: center; }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th { text-align: left; color: var(--muted); font-weight: 500; font-size: 0.7rem;
       text-transform: uppercase; letter-spacing: 0.06em; padding: 0 0 0.75rem; }
  td { padding: 0.5rem 0; border-top: 1px solid var(--border); color: var(--text);
       vertical-align: top; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badge { display: inline-block; font-size: 0.65rem; padding: 2px 8px;
           border-radius: 99px; font-weight: 500; }
  .badge-red    { background: rgba(248,113,113,.15); color: var(--red);    border: 1px solid rgba(248,113,113,.3); }
  .badge-green  { background: rgba(52,211,153,.15);  color: var(--green);  border: 1px solid rgba(52,211,153,.3); }
  .badge-yellow { background: rgba(251,191,36,.15);  color: var(--yellow); border: 1px solid rgba(251,191,36,.3); }
  .badge-accent { background: rgba(99,102,241,.15);  color: var(--accent); border: 1px solid rgba(99,102,241,.3); }
  .full-panel { margin-bottom: 2rem; }
  .pattern-legend { display: flex; flex-direction: column; gap: 6px; font-size: 0.78rem; min-width: 160px; }
  .legend-row { display: flex; align-items: center; gap: 8px; }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .legend-count { margin-left: auto; color: var(--muted); font-variant-numeric: tabular-nums; }
  .donut-inner { display: flex; gap: 1.5rem; align-items: center; }
  #last-updated { font-size: 0.75rem; color: var(--muted); }
</style>
</head>
<body>
<header>
  <div class="live-dot"></div>
  <h1>WAFisGoingOn</h1>
  <div class="header-right">
    <span id="last-updated">Loading&hellip;</span>
    <a id="report-btn" class="report-btn" href="#" onclick="downloadReport(event)">
      &#128196; Export PDF Report
    </a>
  </div>
</header>

<main>
  <div class="metrics">
    <div class="metric">
      <div class="metric-label">Total Requests</div>
      <div class="metric-value" id="m-total">—</div>
    </div>
    <div class="metric">
      <div class="metric-label">Blocked</div>
      <div class="metric-value red" id="m-blocked">—</div>
    </div>
    <div class="metric">
      <div class="metric-label">Allowed</div>
      <div class="metric-value green" id="m-allowed">—</div>
    </div>
    <div class="metric">
      <div class="metric-label">Block Rate</div>
      <div class="metric-value yellow" id="m-rate">—</div>
    </div>
  </div>

  <div class="grid-3">
    <div class="panel" style="grid-column: span 2">
      <h2>Requests / minute (last hour)</h2>
      <div class="chart-wrap"><canvas id="chart-traffic"></canvas></div>
    </div>
    <div class="panel">
      <h2>Attack patterns</h2>
      <div class="donut-wrap">
        <div class="donut-inner">
          <canvas id="chart-donut" width="140" height="140" style="flex-shrink:0"></canvas>
          <div class="pattern-legend" id="legend-patterns"></div>
        </div>
      </div>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel">
      <h2>Top attacking IPs</h2>
      <table>
        <thead><tr><th>IP</th><th>Blocked</th></tr></thead>
        <tbody id="tbl-ips"></tbody>
      </table>
    </div>
    <div class="panel">
      <h2>Pattern breakdown</h2>
      <table>
        <thead><tr><th>Attack type</th><th>Count</th><th>Severity</th></tr></thead>
        <tbody id="tbl-patterns"></tbody>
      </table>
    </div>
  </div>

  <div class="panel full-panel">
    <h2>Recent events</h2>
    <table>
      <thead>
        <tr>
          <th>Time</th><th>IP</th><th>Method</th><th>Path</th>
          <th>Surface</th><th>Attack class</th><th>Score</th><th>Status</th>
        </tr>
      </thead>
      <tbody id="tbl-events"></tbody>
    </table>
  </div>
</main>

<script>
const KEY  = new URLSearchParams(location.search).get('key') || '';
const BASE = location.pathname.replace(/\\/+$/, '');

const SEVERITY = {
  sql_injection: 'HIGH', command_injection: 'HIGH', xxe: 'HIGH', ssrf: 'HIGH',
  xss: 'MEDIUM', path_traversal: 'MEDIUM', template_injection: 'MEDIUM',
  unknown: 'LOW',
};
const SEV_BADGE = { HIGH: 'badge-red', MEDIUM: 'badge-yellow', LOW: 'badge-accent' };

let trafficChart, donutChart;

function initCharts() {
  const tCtx = document.getElementById('chart-traffic').getContext('2d');
  trafficChart = new Chart(tCtx, {
    type: 'line',
    data: { labels: [], datasets: [
      { label: 'Total',   data: [], borderColor: '#6366f1', tension: 0.3, fill: false, pointRadius: 2 },
      { label: 'Blocked', data: [], borderColor: '#f87171', tension: 0.3, fill: false, pointRadius: 2 },
    ]},
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
      scales: {
        x: { ticks: { color: '#475569', maxTicksLimit: 8, font: { size: 10 } }, grid: { color: '#2d3048' } },
        y: { ticks: { color: '#475569', font: { size: 10 } }, grid: { color: '#2d3048' } },
      }
    }
  });

  const dCtx = document.getElementById('chart-donut').getContext('2d');
  donutChart = new Chart(dCtx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 1, borderColor: '#1a1d2e' }] },
    options: {
      responsive: false, cutout: '68%',
      plugins: { legend: { display: false }, tooltip: {
        callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}` }
      }},
    }
  });
}

async function refresh() {
  try {
    const r = await fetch(`${BASE}/api/stats?key=${KEY}`);
    if (!r.ok) { document.getElementById('last-updated').textContent = 'Auth error — check ?key='; return; }
    const d = await r.json();

    document.getElementById('m-total').textContent   = (d.total   || 0).toLocaleString();
    document.getElementById('m-blocked').textContent = (d.blocked || 0).toLocaleString();
    document.getElementById('m-allowed').textContent = (d.allowed || 0).toLocaleString();
    document.getElementById('m-rate').textContent    = (d.block_rate || 0) + '%';
    document.getElementById('last-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();

    // Traffic chart
    trafficChart.data.labels           = d.per_minute.map(r => r.minute.slice(11));
    trafficChart.data.datasets[0].data = d.per_minute.map(r => r.total);
    trafficChart.data.datasets[1].data = d.per_minute.map(r => r.blocked);
    trafficChart.update('none');

    // Donut + legend
    const patterns = (d.attack_patterns || []).filter(p => p.count > 0);
    donutChart.data.labels                        = patterns.map(p => p.label);
    donutChart.data.datasets[0].data              = patterns.map(p => p.count);
    donutChart.data.datasets[0].backgroundColor   = patterns.map(p => p.color);
    donutChart.update('none');
    document.getElementById('legend-patterns').innerHTML = patterns.length
      ? patterns.map(p => `
          <div class="legend-row">
            <span class="legend-dot" style="background:${p.color}"></span>
            <span>${p.icon} ${p.label}</span>
            <span class="legend-count">${p.count}</span>
          </div>`).join('')
      : '<span style="color:var(--muted);font-size:.8rem">No attacks yet</span>';

    // Pattern table
    const allPatterns = d.attack_patterns || [];
    document.getElementById('tbl-patterns').innerHTML = allPatterns.map(p => {
      const sev = SEVERITY[p.name] || 'LOW';
      const bc  = SEV_BADGE[sev];
      return `<tr>
        <td>${p.icon} ${p.label}</td>
        <td>${p.count}</td>
        <td><span class="badge ${bc}">${sev}</span></td>
      </tr>`;
    }).join('');

    // Top IPs
    document.getElementById('tbl-ips').innerHTML = (d.top_ips || []).map(row =>
      `<tr><td>${row.ip}</td><td><span class="badge badge-red">${row.c}</span></td></tr>`
    ).join('') || '<tr><td colspan="2" style="color:var(--muted)">No attacks yet</td></tr>';

    // Events
    document.getElementById('tbl-events').innerHTML = (d.recent || []).map(e => {
      const ts      = e.ts ? e.ts.slice(11,19) : '—';
      const blocked = e.blocked
        ? '<span class="badge badge-red">BLOCKED</span>'
        : '<span class="badge badge-green">ALLOWED</span>';
      const surf  = e.surface && e.surface !== 'none'
        ? `<span class="badge badge-yellow">${e.surface}</span>` : '—';
      const cls   = e.attack_class && e.attack_class !== 'unknown'
        ? `<span class="badge badge-accent">${e.attack_class.replace('_',' ')}</span>` : '—';
      return `<tr>
        <td>${ts}</td>
        <td>${e.ip||'—'}</td>
        <td>${e.method||'—'}</td>
        <td title="${e.path||''}">${(e.path||'—').slice(0,28)}</td>
        <td>${surf}</td>
        <td>${cls}</td>
        <td>${e.score > 0 ? e.score.toFixed(3) : '—'}</td>
        <td>${blocked}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="8" style="color:var(--muted)">No events yet</td></tr>';

  } catch(err) {
    document.getElementById('last-updated').textContent = 'Fetch error: ' + err.message;
  }
}

async function downloadReport(e) {
  e.preventDefault();
  const btn = document.getElementById('report-btn');
  btn.textContent = '⏳ Generating…';
  btn.classList.add('loading');
  try {
    const r = await fetch(`${BASE}/api/report.pdf?key=${KEY}`);
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      alert(j.error || 'Report generation failed — is reportlab installed?');
      return;
    }
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `waf_threat_report_${new Date().toISOString().slice(0,10)}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } catch(err) {
    alert('Download failed: ' + err.message);
  } finally {
    btn.innerHTML = '&#128196; Export PDF Report';
    btn.classList.remove('loading');
  }
}

initCharts();
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    wcfg = CFG["waf"]
    logger.info(f"WAFisGoingOn starting on {wcfg['host']}:{wcfg['port']}")
    logger.info(f"Dashboard: http://127.0.0.1:{wcfg['port']}{DASHBOARD_ROUTE}?key={CFG['dashboard']['api_key']}")
    app.run(host=wcfg["host"], port=wcfg["port"], debug=wcfg.get("debug", False))
