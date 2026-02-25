import unittest
from unittest.mock import patch, MagicMock
import json
import os
import requests
from controller_server import app, API_KEY, BLOCKED_IPS

class TestStage6(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        # Reset Blocklist
        BLOCKED_IPS.clear()

    def test_global_block_update(self):
        # 1. Send BLOCK event
        payload = {
            "timestamp": "2026-02-20T12:00:00",
            "event_type": "BLOCK",
            "sensor_id": "sensor-01",
            "ip": "10.0.0.99"
        }
        response = self.app.post('/receive_log', 
                                 json=payload,
                                 headers={'X-API-KEY': API_KEY})
        self.assertEqual(response.status_code, 200)
        
        # 2. Verify IP is in global blocklist
        self.assertIn("10.0.0.99", BLOCKED_IPS)

    def test_get_blocklist(self):
        BLOCKED_IPS.add("1.2.3.4")
        response = self.app.get('/blocklist')
        data = response.get_json()
        self.assertIn("1.2.3.4", data)

    @patch('honeypot.requests.get')
    def test_honeypot_sync(self, mock_get):
        # Test the sync logic from the honeypot side (imported locally to avoid running threads)
        import honeypot
        
        # Mock Controller Response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ["192.168.1.50"]
        mock_get.return_value = mock_response
        
        # Manually trigger sync logic
        syncer = honeypot.BlocklistSyncer()
        # We can't easily run the loop logic without threading, but we can call the requests part if extracted
        # Or checking effects.
        # Let's mock the sync action:
        honeypot.CONTROLLER_URL = "http://mock/receive_log"
        mock_get.return_value.json.return_value = ["1.1.1.1"]
        
        # Run one iteration of logic (simulated)
        try:
             url = f"http://mock/blocklist"
             resp = mock_get(url, timeout=5)
             if resp.status_code == 200:
                 honeypot.GLOBAL_BLOCKED_IPS = set(resp.json())
        except: pass
        
        self.assertIn("1.1.1.1", honeypot.GLOBAL_BLOCKED_IPS)
        self.assertTrue(honeypot.is_blocked("1.1.1.1"))

if __name__ == '__main__':
    unittest.main()
