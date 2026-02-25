import json
import os
import sys
import logging
from datetime import datetime
from collections import defaultdict
import statistics

# Ensure src/ siblings are importable regardless of CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Try to import patterns from analyzer, or define them if import fails
try:
    from analyzer import LogAnalyzer
except ImportError:
    LogAnalyzer = None

class MetricsGenerator:
    _LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
    _DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'docs')

    def __init__(self, log_file=None, central_log_file=None):
        if log_file is None:
            log_file = os.path.join(self._LOGS_DIR, 'honeypot_logs.json')
        if central_log_file is None:
            central_log_file = os.path.join(self._LOGS_DIR, 'central_logs.json')
        self.log_file = central_log_file if os.path.exists(central_log_file) else log_file
        self.logs = []
        self.analyzer = LogAnalyzer(self.log_file) if LogAnalyzer else None

    def load_logs(self):
        if not os.path.exists(self.log_file):
            logger.warning(f"Log file not found: {self.log_file}")
            return []
        
        try:
            with open(self.log_file, 'r') as f:
                self.logs = json.load(f)
            return self.logs
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
            return []

    def calculate_dwell_time(self):
        """
        Calculates dwell time (duration of SHELL_SESSION) per IP.
        Returns: {ip: {'avg': float, 'max': float, 'sessions': int}}
        """
        sessions = defaultdict(list)
        active_sessions = {} # ip -> start_time

        # Sort logs by timestamp just in case
        sorted_logs = sorted(self.logs, key=lambda x: x.get('timestamp', ''))

        for entry in sorted_logs:
            ip = entry.get('ip')
            event = entry.get('event_type')
            timestamp_str = entry.get('timestamp')
            
            if not ip or not timestamp_str:
                continue

            try:
                ts = datetime.fromisoformat(timestamp_str)
            except ValueError:
                continue

            if event == 'SHELL_SESSION_START':
                active_sessions[ip] = ts
            elif event == 'SHELL_SESSION_END':
                if ip in active_sessions:
                    start_ts = active_sessions.pop(ip)
                    duration = (ts - start_ts).total_seconds()
                    sessions[ip].append(duration)
        
        # Output stats
        results = {}
        for ip, durations in sessions.items():
            if durations:
                results[ip] = {
                    'avg': round(statistics.mean(durations), 2),
                    'max': round(max(durations), 2),
                    'sessions': len(durations)
                }
        return results

    def classify_attacks(self):
        """
        Uses Stage 1 Analyzer logic to classify attacks.
        Returns: {ip: {'patterns': [], 'risk_score': int}}
        """
        if not self.analyzer:
            logger.warning("Analyzer module not available for classification.")
            return {}
        
        # Re-use analyzer logic
        self.analyzer.log_file = self.log_file # Ensure it points to current source
        grouped = self.analyzer.group_by_ip(self.logs)
        
        results = {}
        for ip, events in grouped.items():
            # Analyzer returns a full dict, we just want patterns
            analysis = self.analyzer.analyze_session(ip, events)
            if analysis:
                results[ip] = {
                    'patterns': analysis.get('patterns', []),
                    'risk_score': analysis.get('risk_score', 0)
                }
        return results

    def blocking_efficiency(self):
        """
        Calculates time from First Attempt -> Block.
        Returns: {ip: seconds_to_block}
        """
        first_seen = {}
        block_times = {}

        sorted_logs = sorted(self.logs, key=lambda x: x.get('timestamp', ''))

        for entry in sorted_logs:
            ip = entry.get('ip')
            event = entry.get('event_type')
            timestamp_str = entry.get('timestamp')
            
            if not ip or not timestamp_str:
                continue
            
            try:
                ts = datetime.fromisoformat(timestamp_str)
            except ValueError:
                continue

            if ip not in first_seen:
                first_seen[ip] = ts
            
            if event == 'BLOCK' and ip not in block_times:
                block_times[ip] = (ts - first_seen[ip]).total_seconds()

        return block_times

    def deception_efficiency(self):
        """
        Counts CMD_EXEC per IP (proxy for interaction depth).
        Returns: {ip: command_count}
        """
        counts = defaultdict(int)
        for entry in self.logs:
            if entry.get('event_type') == 'CMD_EXEC':
                ip = entry.get('ip')
                if ip:
                    counts[ip] += 1
        return dict(counts)

    def geographic_distribution(self):
        """
        Mock geographic distribution.
        """
        # In a real system, use GeoIP2 or maxminddb
        # Here we mock based on IP ranges for demonstration
        geo_stats = defaultdict(int)
        for entry in self.logs:
            ip = entry.get('ip')
            if not ip: continue
            
            # Simple mock mapping
            if ip.startswith('192.168.') or ip.startswith('127.'):
                location = "Local Network"
            elif ip.startswith('10.'):
                location = "Internal VPN"
            elif ip.startswith('1.'):
                location = "North America (Mock)"
            elif ip.startswith('2.'):
                location = "Europe (Mock)"
            else:
                location = "Unknown"
            
            # Count unique IPs per location? Or total events? 
            # Usually unique IPs per location is more interesting.
            pass 
            
        # Re-iterate for unique IPs
        unique_ips = set(entry.get('ip') for entry in self.logs if entry.get('ip'))
        for ip in unique_ips:
             if ip.startswith('192.168.') or ip.startswith('127.'):
                location = "Local Network"
             elif ip.startswith('10.'):
                location = "Internal VPN"
             elif ip.startswith('1.'):
                location = "North America (Mock)"
             elif ip.startswith('2.'):
                location = "Europe (Mock)"
             else:
                location = "Unknown"
             geo_stats[location] += 1
             
        return dict(geo_stats)

    def generate_report(self, output_json=None, output_md=None):
        if output_json is None:
            output_json = os.path.join(self._LOGS_DIR, 'experiment_metrics.json')
        if output_md is None:
            output_md = os.path.join(self._DOCS_DIR, 'analysis_report.md')
        self.load_logs()
        
        metrics = {
            'generated_at': datetime.now().isoformat(),
            'total_events': len(self.logs),
            'dwell_time': self.calculate_dwell_time(),
            'attack_classification': self.classify_attacks(),
            'blocking_efficiency': self.blocking_efficiency(),
            'deception_efficiency': self.deception_efficiency(),
            'geographic_distribution': self.geographic_distribution()
        }

        # Save JSON
        try:
            with open(output_json, 'w') as f:
                json.dump(metrics, f, indent=4)
            logger.info(f"Metrics saved to {output_json}")
        except Exception as e:
            logger.error(f"Failed to save JSON metrics: {e}")

        # Save Markdown
        try:
            with open(output_md, 'w') as f:
                f.write(f"# Honeypot Experiment Report\n")
                f.write(f"**Generated:** {metrics['generated_at']}\n")
                f.write(f"**Total Events:** {metrics['total_events']}\n\n")

                f.write("## 1. Dwell Time Analysis\n")
                f.write("| IP | Sessions | Avg Duration (s) | Max Duration (s) |\n")
                f.write("|---|---|---|---|\n")
                for ip, data in metrics['dwell_time'].items():
                    f.write(f"| {ip} | {data['sessions']} | {data['avg']} | {data['max']} |\n")
                
                f.write("\n## 2. Deception Efficiency (Interaction Depth)\n")
                f.write("| IP | Commands Executed |\n")
                f.write("|---|---|\n")
                for ip, count in metrics['deception_efficiency'].items():
                    f.write(f"| {ip} | {count} |\n")

                f.write("\n## 3. Blocking Efficiency\n")
                f.write("| IP | Time to Block (s) |\n")
                f.write("|---|---|\n")
                for ip, seconds in metrics['blocking_efficiency'].items():
                    f.write(f"| {ip} | {round(seconds, 2)} |\n")
                
                f.write("\n## 4. Attack Classification\n")
                f.write("| IP | Risk Score | Patterns |\n")
                f.write("|---|---|---|\n")
                for ip, data in metrics['attack_classification'].items():
                    patterns = ", ".join(data['patterns'])
                    f.write(f"| {ip} | {data['risk_score']} | {patterns} |\n")
            
            logger.info(f"Report saved to {output_md}")
        except Exception as e:
             logger.error(f"Failed to save Markdown report: {e}")

if __name__ == '__main__':
    generator = MetricsGenerator()
    generator.generate_report()
