from flask import Flask, render_template_string, jsonify
import json
import os
from ids_rules import parse_cowrie_logs

app = Flask(__name__)

# Basic HTML template using Bootstrap for a hacker/dashboard aesthetic
TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Alert Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #121212; color: #e0e0e0; font-family: 'Calibri', sans-serif; }
        .card { background-color: #1e1e1e; border: 1px solid #333; margin-bottom: 20px; }
        .card-header { background-color: #000; border-bottom: 1px solid #333; color: #00ff00; font-weight: bold; }
        .alert-row { border-bottom: 1px solid #333; padding: 10px; }
        .alert-title { color: #ff4444; font-weight: bold; }
        .explanation { color: #aaaaaa; font-size: 0.9em; }
        .timestamp { color: #888; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container mt-4">
        <h1 class="mb-4" style="color: #00ff00;">Malik Omar (K2335386) - Security Operations Center Node</h1>
        <p>Live Monitoring: <strong>Cowrie SSH Honeypot (Port 2222)</strong> | <strong>eBPF Kernel Telemetry Active</strong></p>
        
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">
                        Recent Intrusions
                    </div>
                    <div class="card-body p-0">
                        {% for alert in alerts %}
                        <div class="alert-row">
                            <div class="d-flex justify-content-between">
                                <span class="alert-title">{{ alert.rule }}</span>
                                <span class="timestamp">{{ alert.timestamp }}</span>
                            </div>
                            <div style="color: #cccccc;"><strong>Evidence:</strong> {{ alert.evidence }}</div>
                            <div class="mt-2 text-warning"><strong>Explanation:</strong></div>
                            <div class="explanation">{{ alert.explanation }}</div>
                        </div>
                        {% else %}
                        <div class="p-3">No alerts detected in log.</div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    log_path = "../logs/cowrie/cowrie.json"
    if not os.path.exists(log_path):
        alerts = []
    else:
        # Get alerts directly from your existing detection engine logic
        alerts = parse_cowrie_logs(log_path)
        # Reverse to show newest first
        alerts = list(reversed(alerts))
        
    return render_template_string(TEMPLATE, alerts=alerts)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
