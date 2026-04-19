# 🛡️ BruteGuard SOC Platform

**Enterprise-grade brute force detection system** for Windows Security Event Logs, featuring real-time monitoring, machine learning anomaly detection, threat intelligence enrichment, and a professional SOC dashboard.
---


<img width="1911" height="895" alt="Screenshot 2026-04-19 085700" src="https://github.com/user-attachments/assets/e7845570-3164-47a1-b2c8-6b2face2fd4c" />
<img width="1914" height="926" alt="Screenshot 2026-04-19 130539" src="https://github.com/user-attachments/assets/fc954b55-7da5-4d6c-bba4-3bd20d3d6ce4" />
<img width="1919" height="905" alt="image" src="https://github.com/user-attachments/assets/e7ed0aee-1334-49c7-b5e8-80d327006e2d" />





## 📐 Architecture

This is the architecture for this project
```
brute_force_detection/
├── config/
│   └── config.yaml              # Master configuration (all tunables)
├── src/
│   ├── collectors/
│   │   ├── windows_log_collector.py   # Live/EVTX/Simulation collector
│   │   └── simulation.py             # Realistic attack event generator
│   ├── detectors/
│   │   ├── threshold_detector.py     # Rule-based detection engine
│   │   ├── ml_detector.py            # Isolation Forest anomaly detector
│   │   └── pipeline.py              # Multi-threaded orchestrator
│   ├── enrichment/
│   │   └── ip_reputation.py          # AbuseIPDB + GeoIP enrichment
│   ├── response/
│   │   └── alert_manager.py          # Alert lifecycle + notifications
│   ├── database/
│   │   ├── models.py                 # SQLAlchemy ORM models
│   │   └── db_manager.py             # Session management + queries
│   ├── api/
│   │   ├── app.py                    # Flask + SocketIO factory
│   │   └── routes/
│   │       ├── auth.py              # Login/logout endpoints
│   │       ├── dashboard.py         # HTML page routes
│   │       └── api.py               # REST API endpoints
│   ├── reporting/
│   │   └── report_generator.py       # PDF/CSV/JSON report generation
│   └── utils/
│       ├── config_loader.py          # YAML + env var config
│       └── logger.py                 # Structured logging (loguru)
├── dashboard/
│   └── templates/
│       ├── dashboard.html            # SOC dashboard (Chart.js + SocketIO)
│       └── login.html               # Authentication page
├── scripts/
│   └── simulate_attacks.py          # Standalone data generator
├── tests/
│   └── test_detection.py            # 25+ unit & integration tests
├── docker/
│   └── nginx.conf                   # Nginx reverse proxy config
├── main.py                          # Application entry point
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## ⚡ Quick Start

### Option 1: Local Python

```bash
# 1. Clone / extract the project
cd brute_force_detection

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Seed with 7 days of simulation data and start
python main.py --seed

# Dashboard → http://localhost:8000
# Login: admin / admin_changeme_2024!
```

### Option 2: Docker (recommended for demos)

```bash
# Build and start all services
docker compose up --build

# Dashboard → http://localhost:8000
```

### Option 3: Seed only (no web server)

```bash
# Generate 7 days historical data only
python scripts/simulate_attacks.py --days 7 --intensity high

# Then start the server
python main.py --no-pipeline  # Web server only, no live detection
```

---

## 🔑 Default Credentials

| Username | Password                    | Role    |
|----------|-----------------------------|---------|
| admin    | `admin_changeme_2024!`      | admin   |
| analyst  | `analyst_changeme_2024!`    | analyst |

---

## 🔧 Configuration

All tunables live in `config/config.yaml`. Key sections:

```yaml
collection:
  mode: simulation  
  poll_interval_seconds: 5

detection:
  threshold:
    failed_attempts_per_ip: 5    # Brute force trigger
    time_window_seconds: 300     # Detection window

threat_intelligence:
  abuseipdb:
    api_key: "YOUR_KEY_HERE"    # Get free key at abuseipdb.com

alerting:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/..."
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
```

### Environment Variable Overrides

Any config value can be overridden with `BG__` prefixed env vars:

```bash
export BG_COLLECTION__MODE=live
export BG_DETECTION__THRESHOLD__FAILED_ATTEMPTS_PER_IP=10
export BG_THREAT_INTELLIGENCE__ABUSEIPDB__API_KEY=your_key
```

---

## 🎯 Detection Logic

### 1. Threshold Detection (`threshold_detector.py`)

| Pattern             | Trigger Condition                                          | Default Severity |
|---------------------|------------------------------------------------------------|-----------------|
| **Brute Force**     | ≥5 failures from same IP in 5 min                          | HIGH            |
| **User Brute Force**| ≥10 failures against same account in 5 min                 | MEDIUM          |
| **Password Spray**  | 1 IP targeting ≥5 unique usernames in 5 min                | HIGH            |
| **Credential Stuffing** | ≥20 failures across all IPs in 60 seconds              | CRITICAL        |
| **Account Lockout** | Any Event ID 4740                                          | HIGH            |

All windows use **in-memory sliding windows** (no DB round-trips) for microsecond-latency detection. Alert **cooldowns** prevent duplicate alerts for the same (pattern, IP) pair within 2 minutes.

### 2. ML Anomaly Detection (`ml_detector.py`)

Uses **Isolation Forest** trained on 8 engineered features extracted from each IP's rolling 5-minute window:

| Feature              | Description                                    |
|----------------------|------------------------------------------------|
| `fail_count`         | Total failures in window                       |
| `fail_rate_per_min`  | Failures per minute (velocity)                 |
| `username_entropy`   | Shannon entropy of targeted usernames (spray)  |
| `mean_iat_sec`       | Mean inter-arrival time (low = rapid-fire)     |
| `std_iat_sec`        | IAT standard deviation (burstiness)            |
| `unique_users`       | Distinct accounts targeted                     |
| `hour_deviation`     | Deviation from hourly baseline                 |
| `burstiness`         | Coefficient of variation of IAT                |

The model auto-trains on 7 days of historical data at startup if no saved model exists, then saves to `data/models/isolation_forest.pkl` for subsequent runs.

### 3. Threat Intelligence (`ip_reputation.py`)

- **AbuseIPDB**: Abuse confidence score (0–100), category tags, TOR detection
- **ip-api.com**: Country, city, ISP, ASN, lat/lon (free, 45 req/min)
- **SQLite cache**: 24-hour TTL prevents redundant API calls

---

## 📊 Dashboard Features

| Panel                   | Description                                         |
|-------------------------|-----------------------------------------------------|
| **KPI Row**             | Real-time event counts, attack IPs, open alerts     |
| **Login Timeline**      | 6h/24h/72h failure vs success time-series           |
| **Live Alert Feed**     | WebSocket-pushed alerts with 1-click acknowledgment |
| **Top Attack IPs**      | Ranked by failure count with AbuseIPDB scores        |
| **Attack Patterns**     | Doughnut chart of detection type distribution       |
| **Severity Donut**      | Critical/High/Medium/Low breakdown                  |
| **Geographic Origins**  | Country bar chart from GeoIP enrichment             |
| **Hourly Heatmap**      | 24-hour attack intensity pattern (7-day rollup)     |

---

## 🔌 REST API

All endpoints require authentication (session cookie or JSON login).

```
GET  /api/v1/summary                    Dashboard KPIs
GET  /api/v1/events/timeseries          Time-bucketed event counts
GET  /api/v1/events/top-ips             Top attacking IPs with TI data
GET  /api/v1/events/geo                 Geographic attack distribution
GET  /api/v1/alerts                     Alert list (filterable)
POST /api/v1/alerts/{id}/acknowledge    Acknowledge an alert
GET  /api/v1/alerts/export/csv          CSV export
GET  /api/v1/threat-intel/{ip}          On-demand IP enrichment
GET  /api/v1/blocked-ips                Active firewall blocks
POST /api/v1/blocked-ips/{id}/unblock   Remove a block (admin)
GET  /api/v1/ml/status                  ML model status
POST /api/v1/ml/retrain                 Trigger model retraining (admin)
POST /api/v1/reports/generate           Generate PDF/CSV report
```

---

## 🧪 Running Tests

```bash
# Run all tests with coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Run specific test class
pytest tests/test_detection.py::TestThresholdDetector -v

# Quick smoke test
pytest tests/ -x -q
```

---

## 📦 Deployment Notes

### Production Checklist

- [ ] Change default passwords in `config/config.yaml`
- [ ] Set a strong `app.secret_key`
- [ ] Configure real `abuseipdb.api_key`
- [ ] Set `collection.mode: live` (Windows only) or `file`
- [ ] Enable email/Slack alerts
- [ ] Set `database.type: postgresql` for HA deployments
- [ ] Run behind Nginx (`docker compose --profile production up`)
- [ ] Set `app.debug: false`

### Windows Live Mode

On Windows with admin privileges:

```yaml
collection:
  mode: live
  remote_hosts: []   # Add remote hostnames for network monitoring
```

Requires: `pip install pywin32` and run as Administrator.

---

## 🤖 Simulation Modes

```bash
# 7-day high-intensity demo data
python scripts/simulate_attacks.py --days 7 --intensity high

# Spray attacks only, 1000 events
python scripts/simulate_attacks.py --pattern spray --count 1000

# Live real-time stream (Ctrl+C to stop)
python scripts/simulate_attacks.py --live

# Dry run (no DB writes)
python scripts/simulate_attacks.py --days 3 --dry-run
```

---

## 📋 How Detection Works — Technical Depth

### Sliding Window Mechanics

The threshold detector maintains per-IP and per-username `SlidingWindow` objects (Python `list` of `(timestamp, value)` tuples). On each `.count(now)` call, expired entries (older than `window_seconds`) are evicted in O(n) time. For production at scale, swap with a Redis sorted set.

### Isolation Forest

Isolation Forest isolates anomalies by randomly partitioning feature space. Anomalies require fewer splits to isolate (shorter average path length). The `score_samples()` method returns a negative value; values closer to 0 indicate more anomalous behaviour. The `contamination=0.05` parameter assumes 5% of training data is malicious.

### Alert Deduplication

A `_alert_cooldowns` dict maps `(pattern, ip)` → `last_alert_time`. Subsequent triggers within 120 seconds are suppressed. This prevents alert storms during sustained attacks while still logging the continued activity in the event table.

---

*Built as a portfolio project demonstrating enterprise security engineering. For educational and demonstration purposes.*
