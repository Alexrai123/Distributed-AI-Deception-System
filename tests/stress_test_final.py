import threading
import socket
import time
import logging
import paramiko
import os
import signal
from unittest.mock import patch
from honeypot import start_server, SERVER_RUNNING, BLOCKED_IPS, GLOBAL_BLOCKED_IPS
import honeypot

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger("StressTest")

HOST = '127.0.0.1'
PORT = 2222
CONCURRENT_CONNECTIONS = 50

success_count = 0
fail_count = 0
lock = threading.Lock()

def start_infrastructure():
    # Clear any existing blocks
    BLOCKED_IPS.clear()
    GLOBAL_BLOCKED_IPS.clear()
    
    logger.info("Starting Honeypot Server...")
    # signal.signal only works in main thread. We patch it for this test.
    with patch('signal.signal'):
        t = threading.Thread(target=start_server, daemon=True)
        t.start()
    time.sleep(2) # Wait for startup

def attempt_connection(idx):
    global success_count, fail_count
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((HOST, PORT))
        banner = s.recv(1024)
        if b"SSH" in banner:
             with lock:
                 success_count += 1
        else:
             with lock:
                fail_count += 1
        s.close()
    except Exception as e:
        logger.error(f"Connection failed: {e}")
        with lock:
            fail_count += 1

def run_stress_test():
    # Start Server
    start_infrastructure()

    threads = []
    start_time = time.time()
    
    logger.info(f"Starting stress test with {CONCURRENT_CONNECTIONS} concurrent connections...")
    
    for i in range(CONCURRENT_CONNECTIONS):
        t = threading.Thread(target=attempt_connection, args=(i,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    duration = time.time() - start_time
    logger.info(f"Test completed in {duration:.2f}s")
    logger.info(f"Successful Connections: {success_count}")
    logger.info(f"Failed Connections: {fail_count}")

    # Cleanup (Hard kill not needed if daemon, but good practice to stop flag)
    # honeypot.SERVER_RUNNING = False 
    
    if success_count > (CONCURRENT_CONNECTIONS * 0.8):
        logger.info("PASS: Server handled load.")
    else:
        logger.info("FAIL: Server dropped too many connections.")
    
    # We exit the process which kills the daemon thread
    os._exit(0)

if __name__ == "__main__":
    run_stress_test()
