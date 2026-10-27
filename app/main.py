import sys
import os
import shutil
import csv
import io
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Response, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from app.database import get_db_connection

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = FastAPI(title="IoT Rogue Edge Profiler API")

# Setup paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_DIR = os.path.join(BASE_DIR, "data", "uploads")

# Mount the static directory to serve CSS/JS files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
def login_page():
    with open("static/login.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    # Hardcoded credentials for presentation purposes
    if username == "admin" and password == "admin":
        return {"status": "success"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/stats")
def get_stats():
    """Returns high-level statistics for the dashboard header."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM flows")
    total_flows = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM alerts")
    total_alerts = cursor.fetchone()["count"]

    conn.close()
    return {"total_flows": total_flows, "total_alerts": total_alerts}


@app.get("/api/alerts")
def get_alerts():
    """Returns all triggered alerts ordered by newest first."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    alerts = [dict(row) for row in cursor.fetchall()]  # NO LIMITS

    conn.close()
    return {"alerts": alerts}


@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)):
    # Validate file extension
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400, detail="Only .pcap or .pcapng files are allowed"
        )

    # Ensure pcaps directory exists
    os.makedirs("pcaps", exist_ok=True)
    file_path = os.path.join("pcaps", file.filename)

    # Save file to disk
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "status": "success",
        "filename": file.filename,
        "message": "Upload complete",
    }


@app.get("/api/export")
def export_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, rule_name, pcap_name, description, severity, ai_analysis FROM alerts ORDER BY timestamp DESC"
    )
    alerts = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Timestamp",
            "Rule Name",
            "PCAP Source",
            "Description",
            "Severity",
            "AI Analysis",
        ]
    )

    for row in alerts:
        writer.writerow(
            [
                row["timestamp"],
                row["rule_name"],
                row["pcap_name"],
                row["description"],
                row["severity"],
                row["ai_analysis"],
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threat_report.csv"},
    )


@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Accepts PCAP uploads via the API and saves them to data/uploads/."""
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Only .pcap or .pcapng are allowed.",
        )

    file_path = os.path.join(UPLOAD_DIR, file.filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        return {
            "status": "success",
            "message": f"File {file.filename} uploaded successfully.",
            "path": file_path,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not save file: {str(e)}")
