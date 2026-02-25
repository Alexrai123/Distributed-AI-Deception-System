import threading
import time
import os
import json
import requests
import paramiko
import logging
from controller_server import app as controller_app, BLOCKED_IPS
from honeypot import start_server as start_honeypot, SERVER_RUNNING, CLIENT_THREADS, log_writer, blocklist_syncer
import honeypot
import metrics

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Validator")

# Configurations
CONTROLLER_PORT = 5000
HONEYPOT_PORT = 2222
TEST_IP = '127.0.0.1'

def run_controller():
    # Run Flask without reloading to avoid signaling issues in thread
    controller_app.run(host='0.0.0.0', port=CONTROLLER_PORT, use_reloader=False)

def run_honeypot():
    # Set env vars for honeypot to connect to controller
    # We maintain the global imports, but ensure config is set
    honeypot.CONTROLLER_URL = f"http://127.0.0.1:{CONTROLLER_PORT}/receive_log"
    honeypot.SENSOR_ID = "test-sensor"
    start_honeypot()

def wait_for_port(port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except:
            time.sleep(0.5)
    return False

import socket

class SystemValidator:
    def __init__(self):
        self.controller_thread = None
        self.honeypot_thread = None

    def start_infrastructure(self):
        logger.info("Starting Controller...")
        self.controller_thread = threading.Thread(target=run_controller, daemon=True)
        self.controller_thread.start()
        
        if not wait_for_port(CONTROLLER_PORT):
             logger.error("Controller failed to start")
             return False

        logger.info("Starting Honeypot...")
        self.honeypot_thread = threading.Thread(target=run_honeypot, daemon=True)
        self.honeypot_thread.start()
        
        if not wait_for_port(HONEYPOT_PORT):
             logger.error("Honeypot failed to start")
             return False
             
        time.sleep(2) # Stabilize
        return True

    def test_brute_force_block(self):
        logger.info("[TEST] Scenario 1: Brute Force Blocking")
        honeypot.ALLOW_ALL_CREDS = False
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # 1. 6 Failed attempts
        for i in range(6):
            try:
                client.connect('127.0.0.1', port=HONEYPOT_PORT, username='admin', password=f'wrong{i}', timeout=2)
            except paramiko.AuthenticationException:
                pass # Expected
            except Exception as e:
                logger.warning(f"Connection error: {e}")
            client.close()
        
        time.sleep(2) # Wait for log processing and sync
        
        # 2. Verify Global Blocklist
        try:
            resp = requests.get(f"http://127.0.0.1:{CONTROLLER_PORT}/blocklist")
            if '127.0.0.1' in resp.json():
                logger.info("PASS: IP found in Global Blocklist")
            else:
                logger.error("FAIL: 127.0.0.1 NOT in Global Blocklist")
        except Exception as e:
            logger.error(f"FAIL: Could not query blocklist: {e}")

        # 3. Verify Log
        self.check_log_event('BLOCK', '127.0.0.1')

    def test_deception(self):
        logger.info("[TEST] Scenario 2: Deception Interaction")
        honeypot.ALLOW_ALL_CREDS = True
        
        # Clear Blocklists (Controller + Honeypot Local + Honeypot Global)
        if '127.0.0.1' in BLOCKED_IPS:
            BLOCKED_IPS.remove('127.0.0.1')
        if '127.0.0.1' in honeypot.BLOCKED_IPS:
            del honeypot.BLOCKED_IPS['127.0.0.1']
        if '127.0.0.1' in honeypot.GLOBAL_BLOCKED_IPS:
             honeypot.GLOBAL_BLOCKED_IPS.remove('127.0.0.1')
             
        time.sleep(2) # Allow threads to see state change if needed
             
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect('127.0.0.1', port=HONEYPOT_PORT, username='root', password='password', timeout=5)
            chan = client.invoke_shell()
            
            # Send commands
            chan.send("ls /\n")
            time.sleep(1)
            chan.send("whoami\n")
            time.sleep(1)
            
            output = ""
            while chan.recv_ready():
                output += chan.recv(4096).decode('utf-8')
            if "etc" in output and "root" in output:
                logger.info("PASS: Shell Interaction Successful")
            else:
                logger.error(f"FAIL: Unexpected output: {output}")
                
            client.close()
            time.sleep(2)
            
            # Verify Logs
            self.check_log_event('SHELL_SESSION_START', '127.0.0.1')
            self.check_log_event('CMD_EXEC', '127.0.0.1')
            
        except Exception as e:
            logger.error(f"FAIL: Deception test failed: {e}")

    def test_reporting(self):
        logger.info("[TEST] Scenario 3: Reporting")
        try:
            gen = metrics.MetricsGenerator(log_file='logs/honeypot_logs.json', central_log_file='logs/central_logs.json')
            gen.generate_report()
            
            if os.path.exists('logs/experiment_metrics.json') and os.path.exists('docs/analysis_report.md'):
                logger.info("PASS: Reports generated")
            else:
                 logger.error("FAIL: Report files missing")
        except Exception as e:
            logger.error(f"FAIL: Reporting exception: {e}")

    def check_log_event(self, event_type, ip):
        # Check central logs first, then local
        found = False
        files = ['logs/central_logs.json', 'logs/honeypot_logs.json']
        for fname in files:
            if not os.path.exists(fname): continue
            try:
                with open(fname, 'r') as f:
                    logs = json.load(f)
                    for entry in logs:
                        if entry['event_type'] == event_type and entry['ip'] == ip:
                            found = True
                            break
            except: pass
        
        if found:
            logger.info(f"PASS: Logged {event_type} for {ip}")
        else:
             logger.error(f"FAIL: No {event_type} log found for {ip}")

    def stop_infrastructure(self):
        honeypot.SERVER_RUNNING = False
        # Trigger socket break
        try:
             socket.create_connection(('127.0.0.1', HONEYPOT_PORT)).close()
        except: pass

if __name__ == "__main__":
    validator = SystemValidator()
    if validator.start_infrastructure():
        try:
            validator.test_brute_force_block()
            validator.test_deception()
            validator.test_reporting()
        finally:
            validator.stop_infrastructure()
            # Force exit because imported threads might hang
            os._exit(0)
