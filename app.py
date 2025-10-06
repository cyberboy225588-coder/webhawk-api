from flask import Flask, request, jsonify
from scanner import run_full_scan

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
        report_paths = run_full_scan(url)
        return jsonify({
            "status": "completed",
            "target": url,
            "reports": report_paths
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
