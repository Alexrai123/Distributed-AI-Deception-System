import socket
import threading
import json
import time
import logging
import paramiko
import os
import signal
import sys
import queue
import requests
from datetime import datetime

# Ensure src/ siblings are importable regardless of CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deception import CommandSimulator

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
_PROJECT_ROOT = os.environ.get('PROJECT_ROOT', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HOST_KEY_PATH = os.environ.get('HOST_KEY_PATH', os.path.join(_PROJECT_ROOT, 'host.key'))

# Attempt to load or generate the host key immediately so paramiko doesn't crash on load
if not os.path.exists(HOST_KEY_PATH):
    logger.info(f"Generating new RSA host key at {HOST_KEY_PATH}...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)

HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_PATH)
PORT = 2222
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs', 'honeypot_logs.json')
MAX_ATTEMPTS = 5
BLOCK_DURATION = 60
MAX_CONCURRENT_CONNECTIONS = 50
IDLE_TIMEOUT = 120  # Server shuts down if no activity for 120s
CONNECTION_TIMEOUT = 60 # Disconnect client after 60s
ALLOW_ALL_CREDS = os.environ.get('ALLOW_ALL_CREDS', 'False').lower() == 'true' # Stage 3: Allow all for deception

# Stage 4: Distributed Config
CONTROLLER_URL = os.environ.get('CONTROLLER_URL') # e.g. http://controller:5000/receive_log
SENSOR_ID = os.environ.get('SENSOR_ID', socket.gethostname())
API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    logger.warning("API_KEY environment variable is missing! Ensure it is set before deployment.")

# Globals
SERVER_RUNNING = True
BLOCKED_IPS = {}
GLOBAL_BLOCKED_IPS = set()
CLIENT_THREADS = []
LOG_QUEUE = queue.Queue()
connection_semaphore = threading.Semaphore(MAX_CONCURRENT_CONNECTIONS)

class BlocklistSyncer(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True

    def run(self):
        while self.running and SERVER_RUNNING:
            if CONTROLLER_URL:
                try:
                    # Construct URL (assuming /blocklist is relative to base, or hardcoded)
                    # controller_server.py exposes /blocklist
                    base_url = CONTROLLER_URL.rsplit('/', 1)[0]
                    url = f"{base_url}/blocklist"
                    
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        ips = response.json()
                        global GLOBAL_BLOCKED_IPS
                        GLOBAL_BLOCKED_IPS = set(ips)
                        # logger.debug(f"Synced blocklist: {len(GLOBAL_BLOCKED_IPS)} IPs")
                except Exception as e:
                    logger.error(f"Blocklist sync failed: {e}")
            
            time.sleep(10)

class LogWriter(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True

    def run(self):
        while self.running or not LOG_QUEUE.empty():
            try:
                entry = LOG_QUEUE.get(timeout=1.0)
                self._write_log(entry)
                LOG_QUEUE.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"LogWriter error: {e}")

    def _write_log(self, entry):
        # Add Sensor ID
        entry['sensor_id'] = SENSOR_ID
        
        # 1. Try forwarding to Controller
        if CONTROLLER_URL:
            try:
                headers = {'X-API-KEY': API_KEY, 'Content-Type': 'application/json'}
                response = requests.post(CONTROLLER_URL, json=entry, headers=headers, timeout=3)
                if response.status_code != 200:
                    logger.warning(f"Controller returned {response.status_code}")
                    # Fallback to local
                    self._write_local(entry)
                return # Success (or handled failure)
            except requests.RequestException as e:
                logger.error(f"Log forwarding failed: {e}")
                # Fallback to local
                self._write_local(entry)
        else:
            self._write_local(entry)

    def _write_local(self, entry):
        try:
            logs = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, 'r') as f:
                        logs = json.load(f)
                except json.JSONDecodeError:
                    pass
            
            logs.append(entry)
            
            with open(LOG_FILE, 'w') as f:
                json.dump(logs, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to write local log: {e}")

# Initialize Log Writer
log_writer = LogWriter()
log_writer.start()

# Initialize Blocklist Syncer
blocklist_syncer = BlocklistSyncer()
if CONTROLLER_URL:
    blocklist_syncer.start()

def log_event(event_type, ip, username=None, password=None, details=None):
    """
    Queues an event to be logged.
    """
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "ip": ip,
        "username": username,
        "password": password,
        "details": details
    }
    LOG_QUEUE.put(entry)

def is_blocked(ip):
    """
    Checks if an IP is currently blocked without modifying state.
    """
    # Check Global List first
    if ip in GLOBAL_BLOCKED_IPS:
        return True
        
    if ip in BLOCKED_IPS:
        if BLOCKED_IPS[ip]['attempts'] >= MAX_ATTEMPTS:
            if time.time() < BLOCKED_IPS[ip]['until']:
                return True
            else:
                del BLOCKED_IPS[ip]
    return False

def block_ip(ip):
    """
    Checks if an IP has reached the threshold and blocks it if necessary.
    """
    if ip not in BLOCKED_IPS:
        BLOCKED_IPS[ip] = {'attempts': 0, 'until': 0}
    
    BLOCKED_IPS[ip]['attempts'] += 1
    
    if BLOCKED_IPS[ip]['attempts'] >= MAX_ATTEMPTS:
        BLOCKED_IPS[ip]['until'] = time.time() + BLOCK_DURATION
        logger.info(f"Blocked IP {ip} for {BLOCK_DURATION}s")
        log_event("BLOCK", ip, details=f"Blocked for {BLOCK_DURATION}s after {MAX_ATTEMPTS} attempts")

class HoneypotServer(paramiko.ServerInterface):
    """
    Paramiko Server Interface implementation for the Honeypot.
    """
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.simulator = CommandSimulator()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if is_blocked(self.client_ip):
            return paramiko.AUTH_FAILED
            
        logger.info(f"Login attempt: {self.client_ip} - {username}:{password}")
        log_event("LOGIN_ATTEMPT", self.client_ip, username, password)
        
        # Stage 3: Interactive Deception
        # If ALLOW_ALL_CREDS is True, everyone gets in.
        # Otherwise, ONLY allow specific high-value bait credentials to get in.
        is_bait_cred = (username == 'admin' and password == 'admin') or \
                       (username == 'root' and password == '1234')
                       
        if ALLOW_ALL_CREDS or is_bait_cred:
            # Prevent blocking for successful logins during deception
            return paramiko.AUTH_SUCCESSFUL
            
        block_ip(self.client_ip)
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_connection(client_sock, client_addr):
    """
    Handles an individual client connection with strict resource management.
    """
    ip = client_addr[0]
    
    if not connection_semaphore.acquire(blocking=False):
        logger.warning(f"Max connections reached. Rejecting {ip}")
        client_sock.close()
        return

    transport = None
    try:
        client_sock.settimeout(30)
        
        if is_blocked(ip):
            logger.info(f"Connection rejected from blocked IP: {ip}")
            client_sock.send(b"SSH-2.0-OpenSSH_8.2p1\r\n")
            client_sock.close()
            return

        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        
        server = HoneypotServer(ip)
        
        # Explicit timeouts
        transport.start_server(server=server)
        transport.banner_timeout = 15
        transport.auth_timeout = 15
        
        # Wait for auth
        chan = transport.accept(20)
        if chan is None:
            # Auth failed or timeout
            return

        server.event.wait(10)
        if not server.event.is_set():
            logger.warning("Client did not ask for shell.")
            chan.close()
            return
            
        # Interactive Shell Session
        chan.send("Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n\r\n")
        chan.send(f"{server.simulator.user}@{server.simulator.hostname}:~# ")
        
        log_event("SHELL_SESSION_START", ip)
        
        start_time = time.time()
        buf = ""
        session_history = []
        
        while transport.is_active():
            if not SERVER_RUNNING:
                break
                
            if chan.recv_ready():
                data = chan.recv(1024)
                if not data:
                    break
                
                # Simple Char Echo & Buffer
                chars = data.decode('utf-8', errors='ignore')
                should_exit = False
                
                # Check if we should block input for AI evaluation
                # Since we process on enter, we process the whole command synchronously
                # and don't accept new data until it finishes.
                
                for char in chars:
                    # Handle enter
                    if char in ('\r', '\n'):
                        chan.send("\r\n")
                        cmd = buf.strip()
                        if cmd:
                            logger.info(f"Client {ip} executed: {cmd}")
                            
                            # Add to session history
                            session_history.append({"command": cmd})
                            
                            # Pre-Execution AI Evaluation
                            if CONTROLLER_URL:
                                try:
                                    # Filesystem Context Optimization (Current Dir Only)
                                    fs_context = {}
                                    try:
                                        curr_contents = server.simulator.fs.list_dir(server.simulator.current_path)
                                        fs_context = {
                                            "path": server.simulator.current_path,
                                            "contents": curr_contents if curr_contents else []
                                        }
                                    except Exception:
                                        pass

                                    eval_payload = {
                                        "ip": ip,
                                        "command": cmd,
                                        "history": session_history,
                                        "filesystem_context": fs_context
                                    }
                                    
                                    # Controller proxy URL
                                    eval_url = CONTROLLER_URL.replace("/receive_log", "/evaluate_command")
                                    headers = {'X-API-KEY': API_KEY, 'Content-Type': 'application/json'}
                                    
                                    # Strict 5.5-second timeout latency control to allow Mistral inference roundtrip
                                    eval_response = requests.post(eval_url, json=eval_payload, headers=headers, timeout=5.5)
                                    
                                    if eval_response.status_code == 200:
                                        decision = eval_response.json()
                                        action = decision.get("action", "ALLOW")
                                        
                                        if action == "BLOCK":
                                            logger.warning(f"AI Enforcement: Terminating session for {ip} due to blocked command: {cmd}")
                                            chan.send("\r\nConnection terminated by security policy.\r\n")
                                            block_ip(ip)
                                            # Instantly apply to local cache to prevent race condition reconnection
                                            global GLOBAL_BLOCKED_IPS
                                            GLOBAL_BLOCKED_IPS.add(ip)
                                            # Close the connection immediately
                                            should_exit = True
                                            break
                                            
                                        # ALLOW action - check for dynamic decoy
                                        decoy = decision.get("dynamic_decoy", {})
                                        if decoy.get("should_deploy") and decoy.get("path") and decoy.get("content"):
                                            # Deploy the decoy before executing the command so the attacker can see it
                                            logger.info(f"AI Deception: Deploying decoy at {decoy['path']}")
                                            server.simulator.fs.deploy_decoy(decoy["path"], decoy["content"])
                                            
                                except requests.Timeout:
                                    logger.warning("AI Evaluation timeout - Fail Open (ALLOW default)")
                                except Exception as e:
                                    logger.error(f"AI Evaluation failed - Fail Open - error: {e}")
                                
                            
                            output = server.simulator.execute_command(cmd)
                            
                            # Logging CMD_EXEC
                            log_event("CMD_EXEC", ip, details=f"Cmd: {cmd}, Out: {output[:50]}...")
                            
                            if output == "EXIT":
                                should_exit = True
                                break
                                
                            # Convert output newlines for SSH
                            output = output.replace('\n', '\r\n')
                            if output:
                                chan.send(output + "\r\n")
                                
                        buf = ""
                        chan.send(f"{server.simulator.user}@{server.simulator.hostname}:{server.simulator.current_path}# ")
                    
                    # Handle Backspace (del/backspace char)
                    elif char in ('\x7f', '\x08'):
                        if buf:
                            buf = buf[:-1]
                            # Visual backspace
                            chan.send('\x08 \x08')
                    else:
                        buf += char
                        chan.send(char)
                
                if should_exit:
                    break
                    
            time.sleep(0.1)

        duration = round(time.time() - start_time, 1)
        log_event("SHELL_SESSION_END", ip, details=f"Session duration: {duration} seconds")
    except paramiko.SSHException as e:
        logger.warning(f"SSH Error for {ip}: {e}")
    except socket.timeout:
        logger.warning(f"Socket timeout for {ip}")
    except ConnectionResetError:
        logger.warning(f"Connection reset by {ip}")
    except Exception as e:
        logger.error(f"Unexpected error handling {ip}: {e}")
    finally:
        connection_semaphore.release()
        if transport:
            transport.close()
        client_sock.close()
        logger.info(f"Connection closed for {ip}")

def signal_handler(sig, frame):
    global SERVER_RUNNING
    logger.info("Shutdown signal received...")
    SERVER_RUNNING = False
    # Connect to self to unblock accept() if possible or just wait for timeout
    try:
        dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dummy_sock.connect(('127.0.0.1', PORT))
        dummy_sock.close()
    except:
        pass

def start_server():
    global SERVER_RUNNING
    
    import threading
    if threading.current_thread() == threading.main_thread():
        try:
            signal.signal(signal.SIGINT, signal_handler)
        except ValueError:
            pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind(('0.0.0.0', PORT))
    except Exception as e:
        logger.error(f"Bind failed: {e}")
        return
        
    sock.listen(5)
    sock.settimeout(2.0) # check for shutdown
    
    logger.info(f"Honeypot listening on port {PORT}...")
    
    last_activity_time = time.time()
    
    while SERVER_RUNNING:
        # Clean up dead threads
        CLIENT_THREADS[:] = [t for t in CLIENT_THREADS if t.is_alive()]
        
        # Update last activity
        if CLIENT_THREADS:
            last_activity_time = time.time()
            
        try:
            client_sock, client_addr = sock.accept()
            last_activity_time = time.time() # Reset activity on connection
            
            logger.info(f"Accepted connection from {client_addr[0]}")
            
            t = threading.Thread(target=handle_connection, args=(client_sock, client_addr))
            t.daemon = True
            t.start()
            CLIENT_THREADS.append(t)
            
        except socket.timeout:
            continue
        except Exception as e:
            if SERVER_RUNNING:
                logger.error(f"Accept error: {e}")
            break

    logger.info("Server stopping...")
    sock.close()
    log_writer.running = False
    log_writer.join()
    blocklist_syncer.running = False # Stop syncer
    blocklist_syncer.join(timeout=1.0)
    
    for t in CLIENT_THREADS:
        t.join(timeout=1.0)
    logger.info("Server stopped.")

if __name__ == "__main__":
    start_server()
