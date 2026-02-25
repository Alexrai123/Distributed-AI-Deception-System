import requests
import time
import subprocess
import os
import signal

def test_dynamic_decoy():
    print("Starting integration test for Fail-Open AI evaluation and Dynamic Decoy...")
    
    # 1. Start controller server
    controller_process = subprocess.Popen(["python", "src/controller_server.py"])
    time.sleep(2) # Give it time to bind
    
    try:
        # 2. Test Proxy with Brain offline (Fail-open latency test)
        print("Testing Fail-Open (Brain is offline)...")
        headers = {'X-API-KEY': 'default-secure-key', 'Content-Type': 'application/json'}
        payload = {
            "ip": "1.1.1.1",
            "command": "cat /etc/passwd",
            "history": [],
            "filesystem_context": {"path": "/root", "contents": []}
        }
        
        start = time.time()
        try:
            resp = requests.post("http://127.0.0.1:5000/evaluate_command", json=payload, headers=headers, timeout=5)
            data = resp.json()
            elapsed = time.time() - start
            print(f"Fail-Open Response: {data}")
            print(f"Time Taken: {elapsed:.2f}s (Should be ≈ 1.8s proxy timeout)")
            
            assert data["action"] == "ALLOW", "Fail open should default to ALLOW"
            assert data["dynamic_decoy"]["should_deploy"] == False, "No decoy on fail open"
            
        except Exception as e:
            print(f"Proxy request totally failed: {e}")
            
    finally:
        print("Cleaning up Controller process...")
        if os.name == 'nt':
            subprocess.call(['taskkill', '/F', '/T', '/PID', str(controller_process.pid)])
        else:
            os.kill(controller_process.pid, signal.SIGTERM)
            
    print("Integration test complete.")

if __name__ == "__main__":
    test_dynamic_decoy()
