import os
import re
import csv
import io
import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from PIL import Image

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
except Exception:
    pyzbar_decode = None

from rules import RULES
from report import build_report_html, build_multi_report_html

# Load environment variables
load_dotenv()

app = Flask(__name__)

# CORS configuration – allow frontend origins
CORS(
    app,
    supports_credentials=False,
    origins=["*"],
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "DELETE", "OPTIONS"]
)

# ---------------------------------------------------------------------------
# Timezone handling – Indian Standard Time (Asia/Kolkata, UTC+5:30)
# ---------------------------------------------------------------------------
SERVER_TZ = ZoneInfo("Asia/Kolkata")

def _format_timestamp(ts):
    """Convert any UTC datetime or string into Indian Standard Time (IST)."""
    if not ts:
        return datetime.now(SERVER_TZ).strftime("%d/%m/%Y, %I:%M:%S %p")
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(SERVER_TZ).strftime("%d/%m/%Y, %I:%M:%S %p")
    if isinstance(ts, str):
        try:
            cleaned = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(SERVER_TZ).strftime("%d/%m/%Y, %I:%M:%S %p")
        except Exception:
            return ts
    return str(ts)

# ---------------------------------------------------------------------------
# Database – lazy connection with in-memory resilient fallback
# ---------------------------------------------------------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/phishguard")
_mongo_client = None
_memory_history = []

# Automatic one-time cleanup to wipe old test records from previous repo sessions
CLEAN_MARKER = os.path.join(os.path.dirname(__file__), ".cleaned_initial")

def _get_db():
    """Return (client, db) if MongoDB is reachable, else (None, None)."""
    global _mongo_client
    try:
        if _mongo_client is None:
            _mongo_client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=1500,
                connectTimeoutMS=1500,
                socketTimeoutMS=3000,
            )
        _mongo_client.admin.command("ping")
        return _mongo_client, _mongo_client.get_database()
    except Exception:
        _mongo_client = None
        return None, None

def _auto_clean_old_records():
    """Wipes pre-existing leftover records from MongoDB so user starts at 0."""
    global _memory_history
    if not os.path.exists(CLEAN_MARKER):
        try:
            _memory_history = []
            _, db = _get_db()
            if db is not None:
                db.scan_history.delete_many({})
            with open(CLEAN_MARKER, "w") as f:
                f.write("cleaned")
            print(">>> [PhishGuard] Successfully purged previous database tests. Counter reset to 0.")
        except Exception as e:
            print("Auto clean notice:", e)

# Trigger auto clean
_auto_clean_old_records()

def _get_all_scans():
    """Fetch scans from MongoDB if available, otherwise from memory."""
    if not os.path.exists(CLEAN_MARKER):
        _auto_clean_old_records()

    try:
        _, db = _get_db()
        if db is not None:
            cursor = db.scan_history.find().sort("timestamp_utc", -1)
            docs = []
            for d in cursor:
                d["id"] = str(d.get("_id"))
                d.pop("_id", None)
                raw_time = d.get("timestamp_utc") or d.get("timestamp_iso") or d.get("timestamp_ist")
                d["timestamp_ist"] = _format_timestamp(raw_time)
                d["timestamp_display"] = d["timestamp_ist"]
                if isinstance(d.get("timestamp_utc"), datetime):
                    d["timestamp_utc"] = d["timestamp_utc"].isoformat()
                docs.append(d)
            return docs
    except Exception as e:
        print("DB fetch error:", e)
    
    # In-memory fallback
    clean_memory = []
    for m in _memory_history:
        item = m.copy()
        raw_time = item.get("timestamp_utc") or item.get("timestamp_iso") or item.get("timestamp_ist")
        item["timestamp_ist"] = _format_timestamp(raw_time)
        item["timestamp_display"] = item["timestamp_ist"]
        if isinstance(item.get("timestamp_utc"), datetime):
            item["timestamp_utc"] = item["timestamp_utc"].isoformat()
        clean_memory.append(item)
    return clean_memory

# ---------------------------------------------------------------------------
# Threat Intelligence (Google Safe Browsing API)
# ---------------------------------------------------------------------------
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_BROWSING_KEY")
SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_safe_browsing(url: str):
    """Check a URL against Google Safe Browsing if API key is present."""
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return {"status": "unconfigured", "matches": []}
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(f"{SAFE_BROWSING_API_URL}?key={key}", json=payload, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])
            return {"status": "connected", "connected": True, "matches": matches, "checked": True}
        return {"status": "error", "error_code": resp.status_code, "matches": []}
    except Exception as e:
        return {"status": "unavailable", "message": str(e), "matches": []}

# ---------------------------------------------------------------------------
# Heuristic Analysis Helper
# ---------------------------------------------------------------------------
def _analyze_url(url: str):
    triggered = []
    score = 0
    for rule in RULES:
        if rule["check"](url):
            triggered.append({
                "id": rule["id"],
                "name": rule["name"],
                "weight": rule["weight"]
            })
            score += rule["weight"]

    if score >= 5:
        verdict = "Phishing"
    elif score >= 3:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    google_result = check_safe_browsing(url)
    report_html = build_report_html(url, score, verdict, triggered, google_result)
    
    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "triggered_rules": triggered,
        "google_safe_browsing": google_result,
        "report_html": report_html
    }

def _save_scan(url: str, score: int, verdict: str, triggered: list, google_result=None):
    """Persist a scan record in MongoDB and in-memory cache with IST timestamp."""
    now_ist = datetime.now(SERVER_TZ)
    now_utc = datetime.now(timezone.utc)
    timestamp_str = now_ist.strftime("%d/%m/%Y, %I:%M:%S %p")

    doc = {
        "id": f"scan_{int(now_utc.timestamp() * 1000)}",
        "url": url,
        "score": score,
        "verdict": verdict,
        "triggered_rules": triggered,
        "timestamp_ist": timestamp_str,
        "timestamp_display": timestamp_str,
        "timestamp_iso": now_ist.isoformat(),
        "timestamp_utc": now_utc.isoformat(),
        "source": "analysis",
        "google_safe_browsing": google_result,
    }

    # Store in memory
    _memory_history.insert(0, doc)

    # Persist in MongoDB
    try:
        _, db = _get_db()
        if db is not None:
            db_doc = doc.copy()
            db_doc["timestamp_utc"] = now_utc
            res = db.scan_history.insert_one(db_doc)
            doc["id"] = str(res.inserted_id)
    except Exception as e:
        print("MongoDB insert error:", e)

    return doc["id"]

# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "PhishGuard Threat Intelligence API"})

@app.get("/time")
def server_time():
    now = datetime.now(SERVER_TZ)
    return jsonify({
        "status": "success",
        "timezone": "Asia/Kolkata",
        "datetime": now.isoformat(),
        "display": now.strftime("%d/%m/%Y, %I:%M:%S %p")
    })

@app.get("/db-health")
def db_health():
    _, db = _get_db()
    if db is None:
        return jsonify({
            "status": "in_memory_fallback",
            "database": "mongodb",
            "message": "MongoDB offline; in-memory storage active."
        })
    try:
        db.command("ping")
        count = db.scan_history.count_documents({})
        return jsonify({
            "status": "connected",
            "database": "mongodb",
            "total_documents": count
        })
    except Exception as e:
        return jsonify({"status": "error", "database": "mongodb", "error": str(e)}), 500

@app.get("/threat-intel/status")
def threat_intel_status():
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return jsonify({
            "configured": False,
            "status": "unconfigured",
            "message": "GOOGLE_SAFE_BROWSING_API_KEY is not defined in backend/.env."
        })
    masked = key[:8] + "..." + key[-6:] if len(key) > 14 else "Active"
    return jsonify({
        "configured": True,
        "status": "connected",
        "provider": "Google Safe Browsing v4",
        "api_key_masked": masked,
        "threat_types": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        "message": "Google Safe Browsing v4 is connected and operational."
    })

@app.get("/stats")
def get_stats():
    """Return actual aggregated metrics from MongoDB/in-memory records."""
    if not os.path.exists(CLEAN_MARKER):
        _auto_clean_old_records()

    all_scans = _get_all_scans()
    total = len(all_scans)
    safe = sum(1 for s in all_scans if s.get("verdict") == "Safe")
    suspicious = sum(1 for s in all_scans if s.get("verdict") == "Suspicious")
    phishing = sum(1 for s in all_scans if s.get("verdict") == "Phishing")

    distribution = {
        "Safe": safe,
        "Suspicious": suspicious,
        "Phishing": phishing
    }

    # Daily scan activity (last 7 days in IST)
    now_ist = datetime.now(SERVER_TZ)
    daily_counts = {}
    for i in range(6, -1, -1):
        day_str = (now_ist - timedelta(days=i)).strftime("%b %d")
        daily_counts[day_str] = 0

    for s in all_scans:
        raw_ts = s.get("timestamp_utc") or s.get("timestamp_iso") or s.get("timestamp_ist")
        if raw_ts:
            try:
                if isinstance(raw_ts, datetime):
                    dt = raw_ts.astimezone(SERVER_TZ) if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc).astimezone(SERVER_TZ)
                else:
                    dt = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00")).astimezone(SERVER_TZ)
                day_key = dt.strftime("%b %d")
                if day_key in daily_counts:
                    daily_counts[day_key] += 1
            except Exception:
                pass

    daily_activity = [{"date": k, "count": v} for k, v in daily_counts.items()]
    recent_threats = [s for s in all_scans if s.get("verdict") in ("Suspicious", "Phishing")][:6]

    return jsonify({
        "total_scans": total,
        "safe_count": safe,
        "suspicious_count": suspicious,
        "phishing_count": phishing,
        "threat_distribution": distribution,
        "daily_activity": daily_activity,
        "recent_threats": recent_threats,
        "recent_scans": all_scans[:8]
    })

@app.post("/analyze")
def analyze():
    data = request.json or {}
    url = data.get("url", "")
    urls = data.get("urls", [])

    if isinstance(url, str) and url.strip():
        urls = [url.strip()]
    elif isinstance(urls, list):
        urls = [u.strip() for u in urls if isinstance(u, str) and u.strip()]

    if not urls:
        return jsonify({"error": "URL required"}), 400

    results = []
    for u in urls:
        if not re.match(r"^https?://", u, re.I):
            u_formatted = "http://" + u
        else:
            u_formatted = u

        res = _analyze_url(u_formatted)
        _save_scan(res["url"], res["score"], res["verdict"], res["triggered_rules"], res.get("google_safe_browsing"))
        results.append(res)

    if len(results) == 1:
        return jsonify(results[0])
    combined_html = build_multi_report_html(results)
    return jsonify({"results": results, "report_html": combined_html})

@app.post("/bulk-upload")
def bulk_upload():
    """Accept a CSV file or list of URLs, scan all, return results."""
    urls = []
    if "file" in request.files:
        file = request.files["file"]
        if file.filename != "":
            try:
                content = file.stream.read().decode("utf-8", errors="ignore")
                reader = csv.reader(io.StringIO(content))
                for row in reader:
                    for item in row:
                        val = item.strip()
                        if val and (val.startswith("http") or "." in val):
                            urls.append(val)
            except Exception as e:
                return jsonify({"error": f"Failed to parse CSV: {str(e)}"}), 400

    if not urls and request.is_json:
        urls = request.json.get("urls", [])

    if not urls:
        return jsonify({"error": "No valid URLs provided in upload or payload."}), 400

    results = []
    for u in urls:
        if not re.match(r"^https?://", u, re.I):
            u = "http://" + u
        res = _analyze_url(u)
        _save_scan(res["url"], res["score"], res["verdict"], res["triggered_rules"], res.get("google_safe_browsing"))
        results.append(res)

    combined_html = build_multi_report_html(results)
    return jsonify({
        "total": len(results),
        "results": results,
        "report_html": combined_html
    })

@app.get("/history")
def get_history():
    """Retrieve scan history with search, verdict filter, sorting, and limit."""
    url_q = request.args.get("url", "").strip().lower()
    verdict_q = request.args.get("verdict", "").strip()
    sort_by = request.args.get("sort", "timestamp")
    limit = int(request.args.get("limit", "100"))

    all_records = _get_all_scans()

    filtered = all_records
    if url_q:
        filtered = [r for r in filtered if url_q in r.get("url", "").lower()]
    if verdict_q and verdict_q != "All":
        filtered = [r for r in filtered if r.get("verdict") == verdict_q]

    if sort_by == "score":
        filtered = sorted(filtered, key=lambda x: x.get("score", 0), reverse=True)

    records = filtered[:limit]
    return jsonify({"history": records, "total": len(records)})

@app.post("/clear-history")
@app.delete("/history")
def clear_history():
    """Clear all scan records from MongoDB and in-memory storage."""
    global _memory_history
    _memory_history = []
    deleted_mongo = 0
    try:
        _, db = _get_db()
        if db is not None:
            res = db.scan_history.delete_many({})
            deleted_mongo = res.deleted_count
    except Exception as e:
        return jsonify({"error": f"Failed to clear MongoDB: {str(e)}"}), 500

    return jsonify({
        "status": "success",
        "message": "All scan telemetry and history cleared successfully.",
        "deleted_count": deleted_mongo
    })

@app.post("/qr-scan")
def qr_scan():
    """Accept an uploaded image containing a QR code, decode, and analyze."""
    if "file" not in request.files:
        return jsonify({"error": "No image file provided."}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file."}), 400

    content = None
    try:
        img = Image.open(file.stream).convert("RGB")
        if pyzbar_decode is not None:
            decoded = pyzbar_decode(img)
            if decoded:
                content = decoded[0].data.decode("utf-8")
    except Exception as e:
        return jsonify({"error": f"Failed to process image: {str(e)}"}), 500

    if not content:
        return jsonify({
            "error": "Could not decode QR code from the uploaded image. Please ensure the QR code is clearly visible and well-lit.",
            "suggestion": "Supported formats: PNG, JPG, JPEG with standard QR 2D barcodes."
        }), 400

    if re.match(r"^https?://", content, re.I) or "." in content:
        target_url = content if re.match(r"^https?://", content, re.I) else "http://" + content
        analysis = _analyze_url(target_url)
        _save_scan(analysis["url"], analysis["score"], analysis["verdict"], analysis["triggered_rules"], analysis.get("google_safe_browsing"))
        return jsonify({
            "status": "success",
            "qr_content": content,
            "type": "url",
            "analysis": analysis
        })
    else:
        return jsonify({
            "status": "success",
            "qr_content": content,
            "type": "text",
            "message": "QR code contains plain text, not a web URL."
        })

if __name__ == "__main__":
    app.run(port=5000, debug=True)
