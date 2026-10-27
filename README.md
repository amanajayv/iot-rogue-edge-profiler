# IoT and Rogue Edge Profiler

An automated, Zero-Trust network telemetry and anomaly detection pipeline designed to identify vulnerable IoT edge devices, unauthorized local loopback access, and rogue edge communications in real time.

## Key Features
* **Asynchronous Packet Ingestion (PyShark):** Parses raw packet capture streams at Layer 7, filtering for high-value protocols such as MQTT, HTTP, DNS, and TLS to ensure low-latency performance.
* **Relational Storage (SQLite):** Batches extracted network metadata into a lightweight SQL database, transforming sequential packet reads into efficient queries.
* **Heuristic Anomaly Engine:** Executes custom SQL aggregation rules to flag suspicious behaviors, including unencrypted telemetry over port 1883 and high-frequency DNS beaconing.
* **Automated AI SOC Analyst (Google Gemini 2.5 Flash):** Acts as a virtual analyst, automatically generating concise two-line remediation briefs covering what happened and what to resolve, complete with a fallback system.
* **Dynamic Live Dashboard (FastAPI and Tailwind CSS):** Serves a modern dark-mode glassmorphism interface featuring auto-polling, scrollable alert feeds, and real-time telemetry counters.

---

## Tech Stack
* **Backend:** Python, FastAPI, Uvicorn, PyShark
* **Frontend:** Tailwind CSS, HTML5, JavaScript
* **Database:** SQLite
* **AI and ML:** Google GenAI SDK (gemini-2.5-flash)
* **Utilities:** python-dotenv, pytest

---

## Project Structure
```text
auto-threat-hunter/
│
├── app/
│   ├── __init__.py
│   ├── analyzer.py       # Heuristic rule evaluation and AI trigger engine
│   ├── database.py       # SQLite connection and schema management
│   ├── ingestion.py      # PyShark packet parsing and batch insertion
│   ├── main.py           # FastAPI server and REST API endpoints
│   ├── streamer.py       # Live background telemetry and alert simulator
│   └── threat_intel.py   # Gemini API integration and structured fallback
│
├── data/
│   └── threat_hunter.db  # Local SQLite database instance
│
├── pcaps/                # Raw network capture samples
├── static/
│   └── index.html        # Responsive dark-mode Tailwind dashboard
│
├── .env                  # API keys and environment configuration
├── Dockerfile            # Containerization manifest
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation