import logging
import json
from flask import Flask, request, jsonify
from datetime import datetime
import os

app = Flask(__name__)

# Set up logging to append to our own fake cowrie-style json log
LOG_FILE = "/vagrant/logs/cowrie/http_decoy.json"

# suppress flask default stdout
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

def log_event(event_type, req):
    event = {
        "eventid": event_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": req.remote_addr,
        "protocol": "http",
        "method": req.method,
        "path": req.path,
        "headers": dict(req.headers),
        "sensor": "ids-honeypot-web"
    }
    
    # Try to extract credentials if it's a login attempt
    if req.method == "POST":
        if req.is_json:
            event["payload"] = req.json
            event["username"] = req.json.get("username", req.json.get("user", ""))
            event["password"] = req.json.get("password", req.json.get("pass", ""))
        else:
            event["payload"] = dict(req.form)
            event["username"] = req.form.get("username", req.form.get("user", ""))
            event["password"] = req.form.get("password", req.form.get("pass", ""))
            
    try:
        # Ensure dir exists
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        print(f"Error writing to log: {e}")

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    # Log every single incoming request
    
    if request.method == "POST" and ("login" in path.lower() or "auth" in path.lower() or "admin" in path.lower()):
        log_event("cowrie.http.login.failed", request)
        return jsonify({"status": "error", "message": "Invalid device credentials"}), 401
    else:
        log_event("cowrie.http.request", request)
        
    # Return a fake IoT router login page for GET requests
    if request.method == "GET":
        return """
        <html>
            <head><title>Malik Omar (K2335386) - IoT Honey Pot</title></head>
            <body style="text-align:center; margin-top:50px; font-family: 'Calibri', sans-serif;">
                <h2>Malik Omar (K2335386) - IoT Honey Pot</h2>
                <div style="border: 1px solid #ccc; padding: 20px; width: 300px; margin: 0 auto;">
                    <form method="POST" action="/login">
                        <input type="text" name="username" placeholder="Username" style="margin-bottom:10px; width: 100%;"><br>
                        <input type="password" name="password" placeholder="Password" style="margin-bottom:10px; width: 100%;"><br>
                        <button type="submit" style="width: 100%;">Login</button>
                    </form>
                </div>
                <p style="color:red; font-size: 12px; margin-top:20px;">Firmware version: 1.0.4 (Outdated)</p>
            </body>
        </html>
        """, 200
        
    return jsonify({"status": "error", "message": "Method not allowed"}), 405

if __name__ == '__main__':
    print("[*] Starting IoT Honeytoken HTTP Decoy on port 80...")
    app.run(host='0.0.0.0', port=80)
