#!/usr/bin/env python3
"""
dashboard.py — Flask read-only sudo tracker dashboard on localhost:7474.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Lazy import Flask only when run
log = logging.getLogger("dashboard")


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>LinuxAuthGuard · Sudo Dashboard</title>
<style>
  :root{--bg:#0f1117;--card:#1a1d27;--accent:#6c8ef5;--danger:#e05c5c;
        --warn:#f0a832;--text:#e2e4f0;--muted:#8b8fa8;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;
       font-size:14px;padding:24px;}
  h1{font-size:1.4rem;margin-bottom:4px;color:var(--accent);}
  .subtitle{color:var(--muted);margin-bottom:24px;}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
        gap:16px;margin-bottom:24px;}
  .card{background:var(--card);border-radius:12px;padding:20px;}
  .card h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;
            color:var(--muted);margin-bottom:8px;}
  .big{font-size:2.4rem;font-weight:700;}
  .danger{color:var(--danger);}
  .warn{color:var(--warn);}
  table{width:100%;border-collapse:collapse;}
  th{text-align:left;padding:8px 12px;font-size:.75rem;
     text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
     border-bottom:1px solid #2a2d3a;}
  td{padding:8px 12px;border-bottom:1px solid #1e2130;vertical-align:top;}
  tr:last-child td{border:none;}
  .badge{display:inline-block;padding:2px 8px;border-radius:99px;
         font-size:.7rem;font-weight:600;}
  .badge-danger{background:#3d1a1a;color:var(--danger);}
  .badge-ok{background:#1a2d1a;color:#5ec878;}
  .section-title{font-size:1rem;font-weight:600;margin:24px 0 12px;}
  #chart-container{background:var(--card);border-radius:12px;padding:20px;
                   margin-bottom:24px;}
  canvas{max-height:200px;}
  .refresh{float:right;color:var(--muted);font-size:.8rem;}
</style>
</head>
<body>
<h1>🛡 LinuxAuthGuard · Sudo Dashboard</h1>
<p class="subtitle">Read-only view · auto-refreshes every 30 s
  <span class="refresh" id="last-refresh"></span></p>

<div class="grid" id="stats-cards"></div>

<div id="chart-container">
  <h2 style="font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;
             color:var(--muted);margin-bottom:12px;">Sudo events per hour (7 days)</h2>
  <canvas id="chart"></canvas>
</div>

<p class="section-title">⚠ Recent Anomalies</p>
<div class="card" style="margin-bottom:24px;">
  <table><thead><tr>
    <th>Time</th><th>User</th><th>Command</th><th>Reason</th>
  </tr></thead><tbody id="anomaly-table"></tbody></table>
</div>

<p class="section-title">📋 Recent Events</p>
<div class="card">
  <table><thead><tr>
    <th>Time</th><th>User</th><th>Command</th><th>Result</th>
  </tr></thead><tbody id="events-table"></tbody></table>
</div>

<p class="section-title">🔢 Per-User Summary</p>
<div class="card">
  <table><thead><tr>
    <th>User</th><th>Total Sudo</th><th>Anomalies</th><th>Last Seen</th>
  </tr></thead><tbody id="user-table"></tbody></table>
</div>

<script>
async function fetchJSON(url){const r=await fetch(url);return r.json();}

function timeAgo(ts){
  const d=new Date(ts+"Z"),now=new Date();
  const sec=Math.floor((now-d)/1000);
  if(sec<60) return sec+"s ago";
  if(sec<3600) return Math.floor(sec/60)+"m ago";
  return Math.floor(sec/3600)+"h ago";
}

async function refresh(){
  const [stats,anomalies,events,users,hourly]=await Promise.all([
    fetchJSON("/api/stats"),
    fetchJSON("/api/anomalies"),
    fetchJSON("/api/events"),
    fetchJSON("/api/users"),
    fetchJSON("/api/hourly"),
  ]);

  // Stat cards
  document.getElementById("stats-cards").innerHTML=`
    <div class="card"><h2>Total Sudo Events</h2>
      <div class="big">${stats.total}</div></div>
    <div class="card"><h2>Anomalies Detected</h2>
      <div class="big danger">${stats.anomalies}</div></div>
    <div class="card"><h2>Unique Users</h2>
      <div class="big">${stats.unique_users}</div></div>
    <div class="card"><h2>Unique Paths</h2>
      <div class="big">${stats.unique_paths}</div></div>
  `;

  // Anomaly table
  const at=document.getElementById("anomaly-table");
  if(anomalies.length===0){
    at.innerHTML='<tr><td colspan="4" style="color:var(--muted)">No anomalies recorded.</td></tr>';
  } else {
    at.innerHTML=anomalies.slice(0,20).map(r=>`<tr>
      <td>${timeAgo(r.timestamp)}</td>
      <td>${r.username}</td>
      <td style="font-family:monospace;font-size:.8rem">${r.command.slice(0,60)}</td>
      <td><span class="badge badge-danger">${r.anomaly_reason}</span></td>
    </tr>`).join("");
  }

  // Recent events
  document.getElementById("events-table").innerHTML=events.slice(0,30).map(r=>`<tr>
    <td>${timeAgo(r.timestamp)}</td>
    <td>${r.username}</td>
    <td style="font-family:monospace;font-size:.8rem">${r.command.slice(0,70)}</td>
    <td><span class="badge ${r.granted?"badge-ok":"badge-danger"}">${r.granted?"OK":"DENIED"}</span></td>
  </tr>`).join("");

  // User summary
  document.getElementById("user-table").innerHTML=users.map(r=>`<tr>
    <td>${r.username}</td>
    <td>${r.total}</td>
    <td class="${r.anomalies>0?"danger":""}">${r.anomalies}</td>
    <td>${timeAgo(r.last_seen)}</td>
  </tr>`).join("");

  // Chart
  drawChart(hourly);

  document.getElementById("last-refresh").textContent=
    "Last refresh: "+new Date().toLocaleTimeString();
}

function drawChart(hourly){
  const canvas=document.getElementById("chart");
  const ctx=canvas.getContext("2d");
  const W=canvas.width=canvas.parentElement.clientWidth-40;
  const H=canvas.height=180;
  ctx.clearRect(0,0,W,H);
  if(!hourly.length) return;
  const max=Math.max(...hourly.map(h=>h.cnt),1);
  const pad=8, barW=Math.max(2,Math.floor((W-pad*2)/hourly.length)-1);
  hourly.forEach((h,i)=>{
    const bh=Math.floor((h.cnt/max)*(H-20));
    const x=pad+i*(barW+1);
    ctx.fillStyle="#6c8ef533";
    ctx.fillRect(x,H-bh-20,barW,bh);
    ctx.fillStyle="#6c8ef5";
    ctx.fillRect(x,H-bh-20,barW,2);
  });
}

refresh();
setInterval(refresh,30000);
</script>
</body>
</html>
"""


def create_app(db_path: str | None = None) -> "Any":  # type: ignore[return]
    """Create and return the Flask application."""
    from flask import Flask, jsonify  # noqa: PLC0415

    sys.path.insert(0, str(Path(__file__).parent))
    from sudo_db import SudoDatabase  # noqa: PLC0415
    from anomaly_detector import get_recent_anomalies  # noqa: PLC0415

    app = Flask(__name__)
    db = SudoDatabase(db_path)

    @app.route("/")
    def index():  # type: ignore[return]
        from flask import Response  # noqa: PLC0415
        return Response(HTML_TEMPLATE, mimetype="text/html")

    @app.route("/api/stats")
    def api_stats():  # type: ignore[return]
        con = db._con
        total = con.execute("SELECT COUNT(*) FROM sudo_events").fetchone()[0]
        anomalies = con.execute(
            "SELECT COUNT(*) FROM sudo_events WHERE anomaly_flag=1"
        ).fetchone()[0]
        unique_users = con.execute(
            "SELECT COUNT(DISTINCT username) FROM sudo_events"
        ).fetchone()[0]
        unique_paths = con.execute(
            "SELECT COUNT(*) FROM path_stats"
        ).fetchone()[0]
        return jsonify({
            "total": total,
            "anomalies": anomalies,
            "unique_users": unique_users,
            "unique_paths": unique_paths,
        })

    @app.route("/api/anomalies")
    def api_anomalies():  # type: ignore[return]
        return jsonify(get_recent_anomalies(50))

    @app.route("/api/events")
    def api_events():  # type: ignore[return]
        return jsonify(db.get_recent_events(100))

    @app.route("/api/users")
    def api_users():  # type: ignore[return]
        return jsonify(db.get_user_summary())

    @app.route("/api/hourly")
    def api_hourly():  # type: ignore[return]
        return jsonify(db.get_hourly_counts(7))

    return app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LinuxAuthGuard sudo dashboard (localhost:7474)"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7474)
    parser.add_argument("--db", default=None, help="Override DB path")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    try:
        app = create_app(args.db)
    except ImportError as exc:
        print(f"Flask not installed: {exc}\nInstall with: pip install flask",
              file=sys.stderr)
        sys.exit(1)

    print(f"Sudo dashboard running at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)


if __name__ == "__main__":
    main()
