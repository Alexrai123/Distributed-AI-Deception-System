import paramiko
import os
import sys

HOSTNAME = os.environ.get('PI_HOST', '192.168.50.25') # Recommend setting via export PI_HOST=...
USERNAME = os.environ.get('PI_USER', 'alexhudita')
PASSWORD = os.environ.get('PI_PASSWORD')
if not PASSWORD:
    print("Error: PI_PASSWORD environment variable is required.")
    sys.exit(1)
    
LOCAL_DIR = os.environ.get('LOCAL_DIR', r'C:\Users\alexh\OneDrive\Desktop\dsrt')
REMOTE_DIR = f"/home/{USERNAME}/dsrt"

def upload_dir(sftp, local_dir, remote_dir):
    try:
        sftp.mkdir(remote_dir)
    except IOError:
        pass # Directory likely exists

    for item in os.listdir(local_dir):
        if item in ['.git', '__pycache__', 'behavior_report.json', 'honeypot_logs.json', 'experiment_metrics.json']:
            continue
        local_path = os.path.join(local_dir, item)
        remote_path = f"{remote_dir}/{item}"

        if os.path.isfile(local_path):
            print(f"Uploading {local_path} -> {remote_path}")
            sftp.put(local_path, remote_path)
        elif os.path.isdir(local_path):
            upload_dir(sftp, local_path, remote_path)

def connect_and_deploy():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {HOSTNAME}...")
    try:
        client.connect(HOSTNAME, username=USERNAME, password=PASSWORD)
        sftp = client.open_sftp()
        print("Uploading project files...")
        upload_dir(sftp, LOCAL_DIR, REMOTE_DIR)
        
        print("Executing Docker Compose...")
        stdin, stdout, stderr = client.exec_command(f'cd {REMOTE_DIR} && sudo docker compose up --build -d')
        print(stdout.read().decode('utf-8', errors='replace'))
        err = stderr.read().decode('utf-8', errors='replace')
        if err:
            print(f"Errors: {err}")
            
        print("Success! Honeypot deployed to the Raspberry Pi.")
    except Exception as e:
        print(f"Deployment failed: {e}")
    finally:
        if 'sftp' in locals(): sftp.close()
        client.close()

if __name__ == '__main__':
    connect_and_deploy()
