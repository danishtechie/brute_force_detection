Enterprise-grade brute force detection system for Windows Security Logs with real-time monitoring, ML anomaly detection, threat intelligence, and a live SOC dashboard.
🚀 Overview

BruteGuard is designed like a mini Security Operations Center (SOC).

It doesn’t just collect logs — it detects, analyzes, and responds to attacks in real time.

🔍 What it solves
Detects brute force & credential attacks instantly
Identifies abnormal login patterns using ML
Enriches attacker data with threat intelligence
Provides a clean, real-time monitoring dashboard

🧠 Core Features

⚡ Real-Time Detection
Sliding window detection (microsecond latency)
Detects:
Brute force attacks
Password spraying
Credential stuffing
Account lockouts

🤖 Machine Learning
Isolation Forest anomaly detection
Learns normal behavior → flags anomalies
Auto-training on historical data

🌍 Threat Intelligence
AbuseIPDB integration (IP reputation)
GeoIP enrichment (country, ISP, ASN)
Intelligent attack context

📊 SOC Dashboard
Live alert feed (WebSocket)
Attack trends & timelines
Geo-distribution of attackers
Severity breakdown charts
Heatmaps & top attacker IPs

🔌 REST API
Full analytics access
Alert management
Report generation (PDF/CSV)
ML retraining endpoints

🐳 Docker Ready
One-command deployment
Production-ready setup

🏗️ Architecture
Logs → Detection Engine → ML Analysis → Threat Intel → Alerts → Dashboard
🔧 Modules
Collectors → Windows Event Logs (live/file/simulated)
Detectors → Rule-based + ML engine
Enrichment → IP reputation & geo data
Response → Alert lifecycle & notifications
API → Flask + SocketIO backend
Dashboard → Real-time SOC interface

⚡ Quick Start

python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

pip install -r requirements.txt

python main.py --seed

👉 Dashboard: http://localhost:8000

🐳 Option 2: Docker (Recommended)
docker compose up --build
🎯 Option 3: Simulation Mode
python scripts/simulate_attacks.py --days 7 --intensity high
🔐 Default Credentials
Role	Username	Password
Admin	admin	admin_changeme_2024!
Analyst	analyst	analyst_changeme_2024!

⚠️ Change these immediately in production.

🎯 Detection Logic
🔹 Rule-Based Engine
Attack Type	Condition
Brute Force	≥5 failures / IP in 5 min
Password Spray	1 IP → multiple users
Credential Stuffing	High global failure rate
Account Lockout	Event ID 4740
🔹 ML Engine (Isolation Forest)

Uses behavioral features like:

Failure rate
Username entropy
Request timing patterns
Burst activity

Detects unknown and evolving attacks.

📊 Dashboard Capabilities
📈 Login activity timeline
🚨 Real-time alert stream
🌍 Geo attack visualization
🔥 Top attacking IPs
📊 Severity distribution
⏱️ Hourly attack heatmap
🧪 Testing
pytest tests/ -v --cov=src

✔️ Includes unit + integration tests
✔️ Coverage reporting enabled

🚀 Production Deployment

Checklist:

 Change default credentials
 Add AbuseIPDB API key
 Use PostgreSQL instead of SQLite
 Enable Slack/Email alerts
 Run behind Nginx
 Disable debug mode
🤖 Simulation Engine

Generate realistic attack scenarios:

# High intensity attack simulation
python scripts/simulate_attacks.py --days 7 --intensity high

# Password spray simulation
python scripts/simulate_attacks.py --pattern spray --count 1000

# Live streaming attacks
python scripts/simulate_attacks.py --live

Perfect for:

Demos
Testing
Recruiter presentations

🧩 Tech Stack
Backend: Flask, SocketIO
ML: Scikit-learn (Isolation Forest)
Database: SQLite / PostgreSQL
Frontend: Chart.js + WebSockets
DevOps: Docker, Nginx
Logging: Loguru
💡 Why This Project Stands Out

✔ Real-time event processing
✔ ML + rule-based hybrid detection
✔ Full-stack implementation
✔ Threat intelligence integration
✔ Clean SOC-style dashboard
✔ Production-ready architecture

📌 Use Cases
Security Operations Center (SOC) simulation
Cybersecurity portfolio project
Threat detection research
Blue team training environment
📜 License

MIT License

⭐ Support

If you like this project:

⭐ Star the repo
🍴 Fork it
🧠 Contribute improvements
👨‍💻 Author

Danish Maqbool
Cybersecurity | Python | SOC Engineering
