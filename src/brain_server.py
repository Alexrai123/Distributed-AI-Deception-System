import os
import sys
import json
import logging
import psutil
try:
    import pynvml
    pynvml.nvmlInit()
    HAS_NVML = True
except Exception:
    HAS_NVML = False

from flask import Flask, request, jsonify
from flask_cors import CORS

# Ensure src/ siblings are importable regardless of CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from llm_interface import LLMInterface

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Enable CORS for all routes so the browser can securely fetch telemetry
CORS(app)

# Initialize LLM Interface to Mistral API
llm = LLMInterface()

@app.route('/telemetry', methods=['GET'])
def get_telemetry():
    """
    Returns real hardware metrics of the host PC running the Brain Server.
    Used by the dashboard for live hardware monitoring.
    """
    cpu_percent = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory()
    ram_percent = ram.percent
    
    # Try to grab CPU temp if supported (rarely supported on Windows natively via psutil, so we mock a realistic fallback if none)
    cpu_temp = 45.0
    if hasattr(psutil, "sensors_temperatures"):
        temps = psutil.sensors_temperatures()
        if temps and 'coretemp' in temps:
            cpu_temp = temps['coretemp'][0].current

    # Try to grab Nvidia GPU usage
    gpu_percent = 0.0
    if HAS_NVML:
        try:
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)
            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            gpu_percent = float(util.gpu)
        except Exception as e:
            logger.error(f"Failed to read NVML: {e}")

    return jsonify({
        "cpu": cpu_percent,
        "ram": ram_percent,
        "temp": cpu_temp,
        "gpu": gpu_percent
    }), 200

@app.route('/analyze', methods=['POST'])
def analyze_threat():
    """
    Receives attacker profile from a sensor (Raspberry Pi),
    queries the Cloud LLM, and returns an actionable decision.
    """
    data = request.json
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    ip = data.get("ip")
    profile = data.get("profile")

    if not ip or not profile:
        return jsonify({"error": "Missing 'ip' or 'profile' in payload"}), 400

    logger.info(f"Received analysis request for IP: {ip}")

    # Ask the LLM to analyze the behavior
    prompt = llm.generate_prompt(ip, profile)
    raw_response = llm.send_request(prompt)
    
    # Parse the LLM's JSON decision
    decision = llm.parse_response(raw_response)
    
    logger.info(f"AI Decision for {ip}: {decision.get('recommended_action', 'unknown')}")
    
    return jsonify({
        "status": "success",
        "decision": decision
    }), 200

@app.route('/evaluate_command', methods=['POST'])
def evaluate_command():
    """
    Receives an attacker command context and returns an instantaneous 
    ALLOW/BLOCK decision and dynamic decoy payload.
    """
    data = request.json
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    ip = data.get("ip")
    command = data.get("command")
    history = data.get("history", [])
    filesystem_context = data.get("filesystem_context", {})

    if not ip or not command:
        return jsonify({"action": "ALLOW", "reason": "Missing ip or command parameters - Fail Open"}), 400

    logger.info(f"Received evaluation request for IP: {ip} | Command: {command}")

    decision = llm.evaluate_command(ip, command, history, filesystem_context)
    
    logger.info(f"AI Decision for {ip}: {decision.get('action')} - Decoy: {decision.get('dynamic_decoy', {}).get('should_deploy')}")
    
    return jsonify(decision), 200

if __name__ == '__main__':
    # Start the Brain Server on port 6001
    # Listening on 0.0.0.0 so the Raspberry Pi can connect over LAN
    logger.info("Starting AI Brain Server on port 6001...")
    app.run(host='0.0.0.0', port=6001)
