# WAFisGoingOn 🛡️

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A **smart, ML-powered Web Application Firewall** that detects injection attacks and discovery techniques using semantic similarity — not just keyword matching. Operates as a transparent reverse proxy with near-zero latency overhead, a real-time dashboard, and a fully YAML-driven configuration.

---

## ✨ Features

| Feature | Detail |
|---|---|
| **Semantic detection** | `sentence-transformers` embeddings + FAISS index; understands attack *meaning*, not just vocabulary |
| **Full surface inspection** | POST body, GET params, URL path, and suspicious headers all inspected |
| **Per-IP rate limiting** | Configurable requests/minute with burst tolerance |
| **Real-time dashboard** | Live traffic chart, block rate, top attacking IPs, event feed |
| **YAML configuration** | Thresholds, backend, allowlists, block responses, per-route rules — all in one file |
| **Graceful fallback** | No ML deps? Automatic word-cosine fallback — zero crashes |
| **Docker-first** | One command to spin up WAF + target app |
| **Auto-learn** | Confirmed attacks are appended to the payload database |

---

## 🚀 Quick start

### Option A — Docker (recommended)

```bash
git clone https://github.com/you/wafisgoingon.git
cd wafisgoingon
docker compose up --build
```

The WAF is now listening on **http://localhost:5000** and proxying to the included target app.

Dashboard (replace the key if you changed it):
```
http://localhost:5000/waf-dashboard?key=change-me-before-deploying
```

### Option B — Local

```bash
pip install -r requirements.txt
python app.py
```

Set `WAF_DASHBOARD_KEY` and `WAF_BACKEND_HOST` via environment variables or `config.yaml`.

---

## ⚙️ Configuration

All settings live in `config.yaml`. No source edits needed.

```yaml
detection:
  threshold: 0.75          # raise to allow more, lower to block more
  wordlist: "data.txt"     # your attack payload list

route_rules:
  "/login":
    threshold: 0.65        # stricter on sensitive routes

allowlist:
  ips: ["127.0.0.1"]
  paths: ["^/health$", "^/static/.*"]

block:
  format: "html"           # or "json" for API services
```

Environment variable overrides are also supported for CI/CD:

| Variable | Maps to |
|---|---|
| `WAF_BACKEND_HOST` | `backend.host` |
| `WAF_THRESHOLD` | `detection.threshold` |
| `WAF_DASHBOARD_KEY` | `dashboard.api_key` |
| `WAF_LOG_LEVEL` | `logging.level` |

---

## 🏗️ Architecture

```
Client
  │
  ▼
┌─────────────────────────────────┐
│         WAFisGoingOn            │  :5000
│                                 │
│  Rate limiter (per-IP)          │
│        │                        │
│  WAFDetector.inspect()          │
│    ├─ URL path                  │
│    ├─ GET params                │
│    ├─ POST body                 │
│    └─ Headers                   │
│        │                        │
│  EmbeddingDetector              │
│    ├─ sentence-transformers     │
│    ├─ FAISS index               │
│    └─ word-cosine fallback      │
│        │                        │
│  SQLite event log               │
└────────┬────────────────────────┘
         │ (if not blocked)
         ▼
┌─────────────────┐
│   Target App    │  :8000
└─────────────────┘
```

---

## 📊 Dashboard

Hit `http://localhost:5000/waf-dashboard?key=<your-key>` to see:

- **Requests/minute** live line chart (last hour)
- **Block rate** and totals
- **Top attacking IPs**
- **Recent events** — timestamp, IP, method, path, surface hit, similarity score, blocked/allowed

---

## 🧪 Testing it

Fire a normal request:
```bash
curl http://localhost:5000/login \
  -d "userName=admin&password=hunter2" -X POST
```

Fire a SQL injection:
```bash
curl http://localhost:5000/login \
  -d "userName=admin'--&password=x" -X POST
# → 403 blocked
```

Try a path traversal:
```bash
curl "http://localhost:5000/api/search?q=../../../../etc/passwd"
# → 403 blocked
```

---

## 📁 Project structure

```
wafisgoingon/
├── app.py                  ← Main WAF reverse proxy
├── config.yaml             ← All configuration
├── data.txt                ← Attack payload wordlist
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── Dockerfile.target
├── docker-compose.yml
├── waf/
│   ├── __init__.py
│   ├── config.py           ← Config loader + env overrides
│   └── detector.py         ← EmbeddingDetector + WAFDetector
└── target_app/
    └── app.py              ← Demo target application
```

---

## 🔒 Security notes

- The dashboard `api_key` **must** be changed before any public deployment. Set `WAF_DASHBOARD_KEY` via environment variable.
- The default allowlist includes `127.0.0.1` — remove it in production.
- The WAF is a defence-in-depth layer, not a replacement for input validation in your application.

---

## 📄 License

MIT — see [LICENSE](LICENSE).
