# IoT & Rogue Edge Profiler

An AI-driven, Zero-Trust network telemetry dashboard designed to protect non-technical users from compromised smart home devices. Motivated by recent mass-privacy breaches like the 2025 CCTV hacking rackets and smart TV data exfiltrations, this platform monitors local network traffic and translates complex packet data into plain-English, actionable remediation steps using generative AI.

## Key Features

* **Asynchronous Packet Ingestion (PyShark):** Parses raw `.pcap` capture streams at Layer 7, filtering for high-value protocols (MQTT, HTTP, DNS, TLS) to ensure low-latency performance without memory exhaustion.

* **Relational Storage (SQLite for Windows):** Batches extracted network metadata into a lightweight, serverless SQL database, transforming sequential packet reads into structured, queryable data.

* **Heuristic Anomaly Engine:** Executes custom SQL aggregation rules to flag suspicious behaviors, including unencrypted telemetry over port 1883, SSRF loopback abuse, and high-frequency DNS beaconing.

* **Automated AI SOC Analyst (Google Gemini 2.5 Flash):** Acts as a virtual Tier-3 analyst, automatically generating concise two-line remediation briefs covering *What Happened* and *What to Resolve*, complete with a structured fallback system.

* **Dynamic Live Dashboard (FastAPI & Tailwind CSS):** Serves a modern dark-mode Single Page Application (SPA) featuring secure authentication, multi-tab navigation, isolated device threat profiles, CSV reporting, and drag-and-drop PCAP ingestion.

## Tech Stack

* **Backend:** Python, FastAPI, Uvicorn, PyShark, python-multipart

* **Frontend:** Tailwind CSS, HTML5, Vanilla JavaScript

* **Database:** SQLite for Windows (Native `sqlite3`)

* **AI & ML:** Google GenAI SDK (`gemini-2.5-flash`)

* **Utilities:** `python-dotenv`, `pytest`, `httpx`

## Project Structure

```
iot-rogue-edge-profiler/
├── app/
│   ├── __init__.py
│   ├── analyzer.py       # Heuristic rule evaluation and AI trigger engine
│   ├── database.py       # SQLite connection and schema management
│   ├── ingestion.py      # PyShark packet parsing and batch insertion
│   ├── main.py           # FastAPI server and REST API endpoints
│   ├── streamer.py       # Live background telemetry and alert simulator
│   └── threat_intel.py   # Gemini API integration and structured fallback
├── data/
│   └── threat_hunter.db  # Local SQLite database instance
├── pcaps/                # Raw network capture samples
├── static/
│   ├── index.html        # Responsive dark-mode Tailwind dashboard
│   └── login.html        # Secure authentication portal
├── .env                  # API keys and environment configuration (Gitignored)
├── .gitignore            # Git exclusion rules
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation


```

## Installation & Setup

1. **Clone the repository:**

   ```
   git clone https://github.com/your-username/iot-rogue-edge-profiler.git
   cd iot-rogue-edge-profiler
   
   
   ```

2. **Initialize a Python Virtual Environment:**

   ```
   python -m venv .venv
   # On Windows:
   .venv\Scripts\activate
   # On Linux/macOS:
   source .venv/bin/activate
   
   
   ```

3. **Install Dependencies:**

   ```
   pip install -r requirements.txt
   
   
   ```

4. **Environment Configuration:**
   Create a `.env` file in the root directory and add your Google Gemini API key:

   ```
   GEMINI_API_KEY=your_actual_api_key_here
   
   
   ```

## Usage

**1. Start the API & Dashboard Server**
Launch the FastAPI backend using Uvicorn. The `--reload` flag enables hot-reloading for development.

```
uvicorn app.main:app --reload


```

Navigate to `http://127.0.0.1:8000` in your browser. Log in using the default presentation credentials (Admin/Admin or your designated local storage credentials).

**2. Ingest Network Traffic**
You can upload a `.pcap` or `.pcapng` file directly through the *Data Ingestion* tab on the dashboard, or drop files directly into the `pcaps/` directory.

**3. Run the Analyzer**
Open a separate terminal window, activate your virtual environment, and trigger the ingestion pipeline to parse the captures, evaluate heuristics, and fetch AI remediation:

```
python -m app.ingestion


```

The dashboard will automatically poll the SQLite database and update the live feed with identified threats and Gemini SOC Intel.