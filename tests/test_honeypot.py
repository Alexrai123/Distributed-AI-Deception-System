import paramiko
import time
import sys

def test_connection(username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Attempting connection with {username}:{password}...")
        client.connect('127.0.0.1', port=2222, username=username, password=password, timeout=5)
    except paramiko.AuthenticationException:
        print("Authentication failed (Expected)")
    except Exception as e:
        print(f"Connection failed: {e}")
    finally:
        client.close()

def main():
    # Attempt 1
    test_connection("admin", "password123")
    # Attempt 2
    test_connection("root", "toor")
    # Attempt 3
    test_connection("user", "123456")
    # Attempt 4
    test_connection("guest", "guest")
    # Attempt 5
    test_connection("test", "test")
    # Attempt 6 (Should be blocked)
    print("Attempting 6th connection (Should be blocked)...")
    test_connection("blocked_user", "blocked_pass")

if __name__ == "__main__":
    main()
