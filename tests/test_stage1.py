import unittest
import json
import os
import time
from datetime import datetime, timedelta
from analyzer import LogAnalyzer, REPORT_FILE

TEST_LOG_FILE = 'test_logs.json'

class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = LogAnalyzer(log_file=TEST_LOG_FILE)
        # Clean up previous runs
        if os.path.exists(TEST_LOG_FILE):
            os.remove(TEST_LOG_FILE)
        if os.path.exists(REPORT_FILE):
            os.remove(REPORT_FILE)

    def tearDown(self):
        if os.path.exists(TEST_LOG_FILE):
            os.remove(TEST_LOG_FILE)
        # We might want to keep REPORT_FILE for inspection, but usually clean up.
        # os.remove(REPORT_FILE) 

    def create_log_entry(self, ip, username, password, timestamp_offset_seconds=0):
        base_time = datetime.now() - timedelta(minutes=10)
        ts = (base_time + timedelta(seconds=timestamp_offset_seconds)).isoformat()
        return {
            "timestamp": ts,
            "event_type": "LOGIN_ATTEMPT",
            "ip": ip,
            "username": username,
            "password": password,
            "details": None
        }

    def test_brute_force_pattern(self):
        logs = []
        ip = "192.168.1.10"
        # 6 distinct passwords for same user -> Brute Force / Credential Stuffing
        for i in range(6):
            logs.append(self.create_log_entry(ip, "root", f"pass{i}", i*2))
        
        with open(TEST_LOG_FILE, 'w') as f:
            json.dump(logs, f)

        self.analyzer.generate_report()
        
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)

        self.assertIn(ip, report)
        self.assertIn("credential_stuffing", report[ip]['patterns'])
        self.assertTrue(report[ip]['risk_score'] > 25) # Base + Stuffing

    def test_admin_targeting(self):
        logs = []
        ip = "10.0.0.5"
        logs.append(self.create_log_entry(ip, "admin", "123456"))
        
        with open(TEST_LOG_FILE, 'w') as f:
            json.dump(logs, f)

        self.analyzer.generate_report()
        
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)

        self.assertIn("admin_targeting", report[ip]['patterns'])
        self.assertTrue(report[ip]['risk_score'] >= 30)

    def test_high_velocity(self):
        logs = []
        ip = "172.16.0.2"
        # 10 attempts in 10 seconds -> High Velocity
        for i in range(10):
            logs.append(self.create_log_entry(ip, "user", "pass", i))

        with open(TEST_LOG_FILE, 'w') as f:
            json.dump(logs, f)
            
        self.analyzer.generate_report()
        
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)
            
        self.assertIn("high_velocity", report[ip]['patterns'])

    def test_risk_score_cap(self):
        logs = []
        ip = "1.2.3.4"
        # Create enough events to exceed score 100 theoretically
        for i in range(150):
             logs.append(self.create_log_entry(ip, "root", f"pass{i}", i))
             
        with open(TEST_LOG_FILE, 'w') as f:
            json.dump(logs, f)

        self.analyzer.generate_report()
        
        with open(REPORT_FILE, 'r') as f:
            report = json.load(f)
            
        self.assertEqual(report[ip]['risk_score'], 100)

if __name__ == '__main__':
    unittest.main()
