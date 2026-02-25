import unittest
from unittest.mock import patch, MagicMock
import json
import os
import requests
from controller_server import app, API_KEY

class TestStage4(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        self.test_log_file = 'test_central_logs.json'
        # Patch the log file path in controller
        self.patcher = patch('controller_server.CENTRAL_LOG_FILE', self.test_log_file)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)

    def test_receive_log_success(self):
        payload = {
            "timestamp": "2026-02-20T12:00:00",
            "event_type": "TEST_EVENT",
            "sensor_id": "sensor-01",
            "ip": "1.2.3.4"
        }
        response = self.app.post('/receive_log', 
                                 json=payload,
                                 headers={'X-API-KEY': API_KEY})
        
        self.assertEqual(response.status_code, 200)
        
        # Verify file write
        with open(self.test_log_file, 'r') as f:
            logs = json.load(f)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['sensor_id'], "sensor-01")

    def test_receive_log_unauthorized(self):
        response = self.app.post('/receive_log', 
                                 json={},
                                 headers={'X-API-KEY': 'wrong-key'})
        self.assertEqual(response.status_code, 401)

    def test_receive_log_invalid_json(self):
        response = self.app.post('/receive_log', 
                                 data="not json",
                                 headers={'X-API-KEY': API_KEY})
        self.assertEqual(response.status_code, 400)

    def test_receive_log_missing_fields(self):
        payload = {"event_type": "TEST"} # Missing timestamp/sensor_id
        response = self.app.post('/receive_log', 
                                 json=payload,
                                 headers={'X-API-KEY': API_KEY})
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()
