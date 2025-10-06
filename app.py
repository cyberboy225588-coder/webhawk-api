from flask import Flask, request, jsonify
import os
from webhawk_core import run_webhawk_scan

app = Flask(__name__)

@app.route('/')
def home():
    return "✅ WebHawk Backend is Running!"

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        report_paths = run_webhawk_scan(url)
        return jsonify({
            "status": "completed",
            "target": url,
            "reports": {
                "json": report_paths["json"],
                "html": report_paths["html"],
                "pdf": report_paths["pdf"]
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
