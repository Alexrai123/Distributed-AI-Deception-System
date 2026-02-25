import socket
import threading
import time
import sys

HOST = '127.0.0.1'
PORT = 2222

def attempt_connection(conn_id, delay=0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((HOST, PORT))
        if delay:
            time.sleep(delay)
        s.close()
        return True, None
    except Exception as e:
        return False, str(e)

def stress_test_rapid(count=50):
    print(f"--- Rapid Connection Test ({count}) ---")
    start = time.time()
    errors = 0
    for i in range(count):
        success, err = attempt_connection(i)
        if not success:
            print(f"Conn {i} failed: {err}")
            errors += 1
    duration = time.time() - start
    print(f"Completed {count} connections in {duration:.2f}s. Errors: {errors}")

def stress_test_concurrency(count=60):
    print(f"--- Concurrency Test ({count}) ---")
    sockets = []
    print("Opening connections...")
    for i in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((HOST, PORT))
            sockets.append(s)
        except Exception as e:
            print(f"Failed to connect at {i}: {e}")
            
    print(f"Held {len(sockets)} open connections.")
    time.sleep(2)
    print("Closing connections...")
    for s in sockets:
        try:
            s.close()
        except:
            pass

def main():
    print("Starting Stress Test...")
    time.sleep(1) # Give server time to start if just launched
    
    try:
        stress_test_rapid(50)
        time.sleep(1)
        stress_test_concurrency(60) # Should hit the 50 max limit and reject some
    except KeyboardInterrupt:
        print("Test stopped.")

if __name__ == "__main__":
    main()
