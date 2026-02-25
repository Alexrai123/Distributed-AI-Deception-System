from flask import Flask, request, jsonify
import json
import os
import logging
from datetime import datetime
import requests
import threading

from flask_cors import CORS

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app) # Allow dashboard to fetch directly across the local network

# Configuration
LOGS_DIR = os.environ.get('LOGS_DIR', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs'))
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)
CENTRAL_LOG_FILE = os.path.join(LOGS_DIR, 'central_logs.json')
EXPERIMENT_METRICS_FILE = os.path.join(LOGS_DIR, 'experiment_metrics.json')

# Require API_KEY in environment to prevent insecure defaults in production
API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    logger.warning("API_KEY environment variable is missing! Ensure it is set before deployment.")

BRAIN_URL = os.environ.get('BRAIN_URL', 'http://127.0.0.1:6001/analyze')

# Global State
BLOCKED_IPS = set()

def query_brain_server(ip, history):
    """
    Sends the attacker history to the Windows Brain Server and executes 
    the AI's recommended action.
    """
    try:
        # We need a basic profile structure that llm_interface expects
        # In a full implementation, we'd use analyzer.py logic. For now, rapid mock:
        profile = {
            "total_attempts": len([l for l in history if l.get('event_type') == 'LOGIN_ATTEMPT']),
            "duration": "unknown",
            "unique_usernames": list(set([l.get('username') for l in history if l.get('username')])),
            "unique_passwords": list(set([l.get('password') for l in history if l.get('password')])),
            "patterns": [l.get('command') for l in history if l.get('command')],
            "risk_score": 50 # Baseline
        }
        
        payload = {"ip": ip, "profile": profile}
        
        logger.info(f"Querying Brain Server for IP {ip}...")
        response = requests.post(BRAIN_URL, json=payload, timeout=10)
        
        if response.status_code == 200:
            decision = response.json().get('decision', {})
            action = decision.get('recommended_action')
            logger.info(f"Brain Server decision for {ip}: {action}")
            
            if action == 'block' or action == 'Block':
                logger.warning(f"AI RECOMMENDED BLOCK during post-mortem: Logging incident but preventing retroactive ban to allow reconnection.")
                # BLOCKED_IPS.add(ip)  # Disabled to prevent post-session lockouts
        else:
            logger.error(f"Brain Server returned {response.status_code}")
            
    except Exception as e:
        logger.error(f"Failed to query Brain Server: {e}")

def validate_api_key(request):
    key = request.headers.get('X-API-KEY')
    return key == API_KEY

@app.route('/evaluate_command', methods=['POST'])
def proxy_evaluate_command():
    """
    Proxies real-time command evaluation requests from honeypot to brain server.
    Instantly updates local blocklist if AI decides to block.
    """
    if not validate_api_key(request):
        return jsonify({"error": "Unauthorized"}), 401
        
    try:
        data = request.get_json()
        if not data:
            return jsonify({"action": "ALLOW", "reason": "No JSON - Fail Open"}), 400
            
        ip = data.get("ip")
        
        # Brain URL for evaluation
        eval_url = BRAIN_URL.replace("/analyze", "/evaluate_command")
        
        # Proxy request with timeout to the brain (5 sec)
        # We give the controller slightly less time so the honeypot's timeout doesn't fire first
        response = requests.post(eval_url, json=data, timeout=5.0)
        
        if response.status_code == 200:
            decision = response.json()
            
            # Instant Enforcement if BLOCK
            if decision.get("action") == "BLOCK" and ip:
                logger.warning(f"AI RECOMMENDED BLOCK during real-time evaluation: Banning {ip} dynamically!")
                BLOCKED_IPS.add(ip)
                
            # Update Dashboard JSON Feed instantaneously
            try:
                # Mock Geolocation (simulate distinct regions based on IP subsets instead of bundling a heavy GeoIP library on the Pi edge node)
                geo = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
                if ip.startswith("89."): geo = {"country": "Netherlands", "city": "Amsterdam", "isp": "KPN"}
                elif ip.startswith("185."): geo = {"country": "Russia", "city": "Moscow", "isp": "Rostelecom"}
                elif ip.startswith("114."): geo = {"country": "China", "city": "Nanjing", "isp": "China Telecom"}
                elif ip.startswith("177."): geo = {"country": "Brazil", "city": "Sao Paulo", "isp": "Vivo"}
                elif ip.startswith("54."): geo = {"country": "USA", "city": "Ashburn", "isp": "Amazon AWS"}
                elif ip.startswith("192.168."): geo = {"country": "Germany", "city": "Frankfurt", "isp": "Local Testnet Node"}
                elif ip.startswith("80."): geo = {"country": "UK", "city": "London", "isp": "BT"}
                elif ip.startswith("118."): geo = {"country": "South Korea", "city": "Seoul", "isp": "KT"}
                elif ip.startswith("104."): geo = {"country": "South Africa", "city": "Cape Town", "isp": "Vodacom"}
                elif ip.startswith("13."): geo = {"country": "India", "city": "Mumbai", "isp": "Jio"}
                elif ip.startswith("82."): geo = {"country": "Romania", "city": "Bucharest", "isp": "Orange"}
                
                cmd_str = data.get("command", "unknown").strip()
                action_str = decision.get("action", "ALLOW")
                reason_str = decision.get("reason", "Incident logged.")
                risk_val = decision.get("risk_score", 0)
                lat = round(response.elapsed.total_seconds(), 2) if hasattr(response, 'elapsed') else 2.45
                
                # Filter out pure noise from the Intelligence Feed UI
                is_noise = cmd_str.lower() in ["exit", "logout", ""]
                
                if not is_noise:
                    log_entry = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "attacker_ip": ip,
                        "geolocation": geo,
                        "command": cmd_str,
                        "ai_decision": action_str,
                        "ai_justification": reason_str,
                        "risk_score": risk_val,
                        "latency": lat,
                        "summary": f"Attacker executed: {cmd_str[:30]}..." if len(cmd_str) > 30 else f"Attacker executed: {cmd_str}"
                    }
                    
                    metrics_data = []
                    if os.path.exists(EXPERIMENT_METRICS_FILE):
                        try:
                            with open(EXPERIMENT_METRICS_FILE, 'r') as f:
                                content = f.read().strip()
                                if content:
                                    metrics_data = json.loads(content)
                        except Exception:
                            pass
                    
                    metrics_data.append(log_entry)
                    
                    with open(EXPERIMENT_METRICS_FILE, 'w') as f:
                        json.dump(metrics_data, f, indent=4)
                    
            except Exception as e:
                logger.error(f"Failed to update experiment_metrics UI feed: {e}")
                
            return jsonify(decision), 200
        else:
            logger.error(f"Brain Server returned {response.status_code} during evaluation proxy")
            return jsonify({"action": "ALLOW", "reason": "Brain Server Error - Fail Open"}), 500
            
    except requests.Timeout:
        logger.error("Brain Server timed out during real-time evaluation proxy")
        return jsonify({"action": "ALLOW", "reason": "Timeout - Fail Open"}), 504
    except Exception as e:
        logger.error(f"Error Proxying Evaluation: {e}")
        return jsonify({"action": "ALLOW", "reason": "Internal Error - Fail Open"}), 500

@app.route('/blocklist', methods=['GET'])
def get_blocklist():
    # Helper to return list of blocked IPs
    return jsonify(list(BLOCKED_IPS))

@app.route('/unblock/<ip>', methods=['GET'])
def unblock_ip(ip):
    # Remove IP from Global Blocklist idempotently
    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)
        logger.info(f"Global Blocklist updated: Removed {ip}")
    return jsonify({"status": "success", "message": f"{ip} is unblocked"}), 200

@app.route('/api/metrics', methods=['GET'])
def serve_metrics():
    """Serves the intelligence feed directly to the Windows dashboard UI."""
    try:
        if os.path.exists(EXPERIMENT_METRICS_FILE):
            with open(EXPERIMENT_METRICS_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    return jsonify(json.loads(content)), 200
        return jsonify([]), 200
    except Exception as e:
        logger.error(f"Error serving metrics JSON: {e}")
        return jsonify({"error": "Failed to read internal AI logs"}), 500

@app.route('/receive_log', methods=['POST'])
def receive_log():
    # Optional Security Check
    if not validate_api_key(request):
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = request.get_json()
        if not data:
             return jsonify({"error": "Invalid JSON"}), 400
        
        # Basic Validation
        required_fields = ['timestamp', 'event_type', 'sensor_id']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing field: {field}"}), 400

        # Log Aggregation
        try:
            logs = []
            if os.path.exists(CENTRAL_LOG_FILE):
                with open(CENTRAL_LOG_FILE, 'r') as f:
                    logs = json.load(f)
            
            logs.append(data)
            
            with open(CENTRAL_LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=4) # In prod, append to file stream or DB
                
            logger.info(f"Received log from {data.get('sensor_id')}: {data.get('event_type')}")
            
            # Stage 6: Orchestration - Update Blocklist
            if data.get('event_type') == 'BLOCK':
                ip = data.get('ip')
                if ip:
                    BLOCKED_IPS.add(ip)
                    logger.info(f"Global Blocklist updated: Added {ip}")
            
            # Stage 7: AI Feedback Loop & Intelligence Feed Trigger
            if data.get('event_type') == 'SHELL_SESSION_END':
                ip = data.get('ip')
                details = data.get('details', 'Session ended')
                if ip:
                    # Append Dwell Time to Dashboard Intelligence Feed
                    try:
                        geo = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
                        if ip.startswith("89."): geo = {"country": "Netherlands", "city": "Amsterdam", "isp": "KPN"}
                        elif ip.startswith("185."): geo = {"country": "Russia", "city": "Moscow", "isp": "Rostelecom"}
                        elif ip.startswith("114."): geo = {"country": "China", "city": "Nanjing", "isp": "China Telecom"}
                        elif ip.startswith("177."): geo = {"country": "Brazil", "city": "Sao Paulo", "isp": "Vivo"}
                        elif ip.startswith("54."): geo = {"country": "USA", "city": "Ashburn", "isp": "Amazon AWS"}
                        elif ip.startswith("192.168."): geo = {"country": "Germany", "city": "Frankfurt", "isp": "Local Testnet Node"}
                        elif ip.startswith("80."): geo = {"country": "UK", "city": "London", "isp": "BT"}
                        elif ip.startswith("118."): geo = {"country": "South Korea", "city": "Seoul", "isp": "KT"}
                        elif ip.startswith("104."): geo = {"country": "South Africa", "city": "Cape Town", "isp": "Vodacom"}
                        elif ip.startswith("13."): geo = {"country": "India", "city": "Mumbai", "isp": "Jio"}
                        elif ip.startswith("82."): geo = {"country": "Romania", "city": "Bucharest", "isp": "Orange"}

                        log_entry = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "attacker_ip": ip,
                            "geolocation": geo,
                            "command": "CONNECTION TERMINATED",
                            "ai_decision": "DISCONNECT",
                            "ai_justification": details,
                            "risk_score": 0,
                            "latency": 0.0,
                            "summary": f"Attacker disconnected. {details}"
                        }

                        metrics_data = []
                        if os.path.exists(EXPERIMENT_METRICS_FILE):
                            with open(EXPERIMENT_METRICS_FILE, 'r') as f:
                                content = f.read().strip()
                                if content:
                                    metrics_data = json.loads(content)
                        metrics_data.append(log_entry)
                        with open(EXPERIMENT_METRICS_FILE, 'w') as f:
                            json.dump(metrics_data, f, indent=4)
                    except Exception as e:
                        logger.error(f"Failed to update metrics for SESSION_END: {e}")

                    # Gather history for this IP from central log
                    # history = [l for l in logs if l.get('ip') == ip]
                    # threading.Thread(target=query_brain_server, args=(ip, history), daemon=True).start()

            return jsonify({"status": "success"}), 200

        except Exception as e:
            logger.error(f"Failed to write central log: {e}")
            return jsonify({"error": "Internal Server Error"}), 500

    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return jsonify({"error": "Bad Request"}), 400

if __name__ == '__main__':
    # Run on all interfaces for Docker compatibility
    app.run(host='0.0.0.0', port=5000)
