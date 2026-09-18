import json
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

load_dotenv()

from analyzer.heuristics import run_heuristics
from analyzer.impersonation import detect_impersonation
from analyzer.risk_engine import calculate_risk
from analyzer.url_parser import parse_url
from database.db import get_db, init_db

app = Flask(__name__)
# The extension talks only to the local Flask server during the hackathon.
CORS(app, resources={r"/api/*": {"origins": "*"}})

ALLOWED_SOURCES = {"popup", "context", "clipboard", "qr", "content"}
MAX_URL_LENGTH = 2000


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "service": "CyberCheck Backend",
    })


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    url_str = data.get("url")
    source = data.get("source", "popup")

    if not isinstance(url_str, str):
        return jsonify({"error": "URL must be a string."}), 400

    url_str = url_str.strip()
    if not url_str:
        return jsonify({"error": "No URL provided."}), 400

    if len(url_str) > MAX_URL_LENGTH:
        return jsonify({"error": "URL too long."}), 400

    if not isinstance(source, str) or source not in ALLOWED_SOURCES:
        source = "popup"

    url_info = parse_url(url_str)
    if not url_info["valid"]:
        return jsonify({"error": url_info["error"] or "Invalid HTTP(S) URL."}), 400

    findings = run_heuristics(url_info, url_str)
    impersonation = detect_impersonation(url_info["domain"], url_str)
    findings.extend(impersonation["findings"])

    risk = calculate_risk(findings, impersonation)
    timestamp = datetime.now(timezone.utc).isoformat()

    result = {
        "url": url_str,
        "normalized_url": url_info["normalized_url"],
        "domain": url_info["domain"],
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "message": risk["message"],
        "findings": findings,
        "impersonated_brand": impersonation["possible_brand"],
        "similarity_score": impersonation["similarity_score"],
        "source": source,
        "timestamp": timestamp,
    }

    try:
        conn = get_db()
        conn.execute(
            """
            INSERT INTO scans
            (url, normalized_url, domain, risk_score, risk_level,
             findings_json, impersonated_brand, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["url"],
                result["normalized_url"],
                result["domain"],
                result["risk_score"],
                result["risk_level"],
                json.dumps(result["findings"]),
                result["impersonated_brand"],
                result["source"],
            ),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        # Analysis remains usable if the local history database is unavailable.
        app.logger.warning("DB save error: %s", exc)

    return jsonify(result)


@app.get("/api/history")
def history():
    try:
        limit = request.args.get("limit", default=20, type=int)
        if limit is None:
            limit = 20
        limit = max(1, min(limit, 100))

        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()

        results = []
        for row in rows:
            try:
                findings = json.loads(row["findings_json"] or "[]")
            except json.JSONDecodeError:
                findings = []

            results.append({
                "id": row["id"],
                "url": row["url"],
                "normalized_url": row["normalized_url"],
                "domain": row["domain"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "findings": findings,
                "impersonated_brand": row["impersonated_brand"],
                "source": row["source"],
                "timestamp": row["timestamp"],
            })

        return jsonify(results)
    except Exception:
        app.logger.exception("History lookup failed")
        return jsonify({"error": "Unable to read scan history."}), 500


# Initialize the database for both `python backend/app.py` and WSGI servers.
init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
