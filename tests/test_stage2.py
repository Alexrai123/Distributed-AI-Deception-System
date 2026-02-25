import unittest
from unittest.mock import patch, MagicMock
import json
import requests
from llm_interface import LLMInterface

class TestLLMInterface(unittest.TestCase):

    def setUp(self):
        self.llm = LLMInterface(timeout=1, max_retry=0)
        self.test_profile = {
            "unique_usernames": ["root", "admin"],
            "risk_score": 80,
            "patterns": ["brute_force"]
        }

    @patch('requests.post')
    def test_check_availability_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        self.assertTrue(self.llm.check_availability())

    @patch('requests.post')
    def test_check_availability_failure(self, mock_post):
        mock_post.side_effect = requests.exceptions.RequestException("Connection refused")
        self.assertFalse(self.llm.check_availability())

    @patch('requests.post')
    def test_send_request_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        # Ollama format {"response": "..."}
        mock_response.json.return_value = {"response": '{"intent": "test"}'}
        mock_post.return_value = mock_response
        
        response = self.llm.send_request("prompt")
        self.assertEqual(response, '{"intent": "test"}')

    def test_parse_response_valid_json(self):
        raw_json = '{"intent": "recon", "sophistication": "low", "recommended_action": "block", "summary": "test"}'
        parsed = self.llm.parse_response(raw_json)
        self.assertEqual(parsed['intent'], "recon")

    def test_parse_response_markdown_json(self):
        raw_json = '```json\n{"intent": "recon", "sophistication": "low", "recommended_action": "block", "summary": "test"}\n```'
        parsed = self.llm.parse_response(raw_json)
        self.assertEqual(parsed['intent'], "recon")

    def test_parse_response_malformed(self):
        raw_json = 'not json'
        parsed = self.llm.parse_response(raw_json)
        self.assertEqual(parsed['intent'], "unknown")

    @patch.object(LLMInterface, 'send_request')
    def test_analyze_attacker(self, mock_send):
        mock_send.return_value = '{"intent": "recon", "sophistication": "low", "recommended_action": "block", "summary": "test"}'
        
        enriched = self.llm.analyze_attacker("1.2.3.4", self.test_profile.copy())
        
        self.assertEqual(enriched['intent'], "recon")
        self.assertEqual(enriched['risk_score'], 80) # preserved

if __name__ == '__main__':
    unittest.main()
