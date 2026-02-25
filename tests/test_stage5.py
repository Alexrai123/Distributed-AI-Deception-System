import unittest
import json
import os
from datetime import datetime, timedelta
from metrics import MetricsGenerator

class TestStage5(unittest.TestCase):

    def setUp(self):
        self.test_log_file = 'test_metrics_logs.json'
        # Create dummy logs
        self.logs = [
            # IP1: immediate block
            {"timestamp": "2026-02-20T10:00:00", "event_type": "LOGIN_ATTEMPT", "ip": "1.1.1.1"},
            {"timestamp": "2026-02-20T10:00:05", "event_type": "BLOCK", "ip": "1.1.1.1"},
            
            # IP2: Shell session (Dwell time testing)
            {"timestamp": "2026-02-20T11:00:00", "event_type": "SHELL_SESSION_START", "ip": "2.2.2.2"},
            {"timestamp": "2026-02-20T11:00:10", "event_type": "CMD_EXEC", "ip": "2.2.2.2"},
            {"timestamp": "2026-02-20T11:00:20", "event_type": "CMD_EXEC", "ip": "2.2.2.2"},
            {"timestamp": "2026-02-20T11:00:30", "event_type": "SHELL_SESSION_END", "ip": "2.2.2.2"},
            
            # IP2: Another short session
            {"timestamp": "2026-02-20T11:05:00", "event_type": "SHELL_SESSION_START", "ip": "2.2.2.2"},
            {"timestamp": "2026-02-20T11:05:05", "event_type": "SHELL_SESSION_END", "ip": "2.2.2.2"},
        ]
        
        with open(self.test_log_file, 'w') as f:
            json.dump(self.logs, f)

        self.generator = MetricsGenerator(log_file=self.test_log_file, central_log_file=self.test_log_file)
        self.generator.load_logs()

    def tearDown(self):
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)
        if os.path.exists('experiment_metrics.json'):
            os.remove('experiment_metrics.json')
        if os.path.exists('analysis_report.md'):
            os.remove('analysis_report.md')

    def test_dwell_time(self):
        results = self.generator.calculate_dwell_time()
        self.assertIn('2.2.2.2', results)
        # Session 1: 30s, Session 2: 5s. Avg: 17.5. Max: 30
        self.assertEqual(results['2.2.2.2']['max'], 30.0)
        self.assertEqual(results['2.2.2.2']['avg'], 17.5)
        self.assertEqual(results['2.2.2.2']['sessions'], 2)

    def test_blocking_efficiency(self):
        results = self.generator.blocking_efficiency()
        self.assertIn('1.1.1.1', results)
        self.assertEqual(results['1.1.1.1'], 5.0)

    def test_deception_efficiency(self):
        results = self.generator.deception_efficiency()
        self.assertIn('2.2.2.2', results)
        self.assertEqual(results['2.2.2.2'], 2) # 2 CMD_EXECs

    def test_geographic_distribution(self):
        # 1.1.1.1 -> NA, 2.2.2.2 -> EU (Mock logic)
        results = self.generator.geographic_distribution()
        self.assertIn('North America (Mock)', results)
        self.assertEqual(results['North America (Mock)'], 1)
        self.assertIn('Europe (Mock)', results)
        self.assertEqual(results['Europe (Mock)'], 1)

    def test_report_generation(self):
        self.generator.generate_report(output_json='experiment_metrics.json', output_md='analysis_report.md')
        self.assertTrue(os.path.exists('experiment_metrics.json'))
        self.assertTrue(os.path.exists('analysis_report.md'))

if __name__ == '__main__':
    unittest.main()
