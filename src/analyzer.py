import json
import os
import logging
from datetime import datetime

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration Constants
_LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
LOG_FILE = os.path.join(_LOGS_DIR, 'honeypot_logs.json')
REPORT_FILE = os.path.join(_LOGS_DIR, 'behavior_report.json')

# Scoring Configuration
BASE_SCORE_PER_ATTEMPT = 1
HIGH_VELOCITY_THRESHOLD = 5  # Attempts per minute
HIGH_VELOCITY_SCORE = 20
ADMIN_TARGETING_SCORE = 30
CREDENTIAL_STUFFING_SCORE = 25
BRUTE_FORCE_SCORE = 20
RISK_SCORE_CAP = 100

ADMIN_USERNAMES = {'root', 'admin', 'administrator', 'sysadmin'}

class LogAnalyzer:
    """
    Processes honeypot_logs.json and extracts attacker behavioral insights.
    """

    def __init__(self, log_file=LOG_FILE):
        self.log_file = log_file

    def load_logs(self):
        """
        Loads honeypot_logs.json.
        Handles missing or corrupted files with proper error messages.
        Returns:
            list of dicts: Raw log events
        """
        if not os.path.exists(self.log_file):
            logger.error(f"Log file not found: {self.log_file}")
            return []

        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logger.error("Invalid log format: Root element must be a list.")
                    return []
                return logs
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON logs: {e}")
            return []
        except Exception as e:
            logger.error(f"Error loading logs: {e}")
            return []

    def group_by_ip(self, logs):
        """
        Aggregates events by source IP.
        Returns:
            dict: {ip_address: [list of events]}
        """
        grouped = {}
        for event in logs:
            ip = event.get('ip')
            if not ip:
                continue
            if ip not in grouped:
                grouped[ip] = []
            grouped[ip].append(event)
        return grouped

    def analyze_session(self, ip, events):
        """
        Analyze events for a single IP.
        
        Extract metrics, detect patterns, and compute risk score.
        """
        if not events:
            return None

        # Sort events by timestamp
        try:
            sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''))
        except Exception:
            sorted_events = events

        # Basic Metrics
        first_event = sorted_events[0]
        last_event = sorted_events[-1]
        
        first_seen_str = first_event.get('timestamp')
        last_seen_str = last_event.get('timestamp')
        
        try:
            first_seen_dt = datetime.fromisoformat(first_seen_str)
            last_seen_dt = datetime.fromisoformat(last_seen_str)
            duration = (last_seen_dt - first_seen_dt).total_seconds()
        except ValueError:
            duration = 0

        usernames = {e.get('username') for e in sorted_events if e.get('username')}
        passwords = {e.get('password') for e in sorted_events if e.get('password')}
        
        total_attempts = sum(1 for e in sorted_events if e.get('event_type') == 'LOGIN_ATTEMPT')
        
        # Pattern Detection & Scoring
        patterns = []
        score_details = {}
        risk_score = 0
        
        # 1. Base Score
        base_points = total_attempts * BASE_SCORE_PER_ATTEMPT
        risk_score += base_points
        score_details['base_attempt_points'] = base_points

        # 2. High Velocity
        # Simple check: attempts / duration (in mins). If duration < 60s, checking raw count might be safer.
        # Strict logic: calculate max attempts in any sliding 60s window would be better, but simple average for now.
        duration_minutes = max(duration / 60.0, 1.0) # avoid div by zero
        attempts_per_min = total_attempts / duration_minutes
        
        if attempts_per_min > HIGH_VELOCITY_THRESHOLD:
            patterns.append('high_velocity')
            risk_score += HIGH_VELOCITY_SCORE
            score_details['high_velocity_bonus'] = HIGH_VELOCITY_SCORE

        # 3. Admin Targeting
        if any(u.lower() in ADMIN_USERNAMES for u in usernames):
            patterns.append('admin_targeting')
            risk_score += ADMIN_TARGETING_SCORE
            score_details['admin_targeting_bonus'] = ADMIN_TARGETING_SCORE

        # 4. Credential Stuffing (Many Passwords, Few Usernames)
        if len(usernames) == 1 and len(passwords) > 3:
            patterns.append('credential_stuffing')
            risk_score += CREDENTIAL_STUFFING_SCORE
            score_details['credential_stuffing_bonus'] = CREDENTIAL_STUFFING_SCORE

        # 5. Brute Force (Many Usernames OR Many Passwords)
        if len(usernames) > 3 or len(passwords) > 5:
            if 'credential_stuffing' not in patterns: # don't double count usually, but let's keep it simple
                patterns.append('brute_force')
                risk_score += BRUTE_FORCE_SCORE
                score_details['brute_force_bonus'] = BRUTE_FORCE_SCORE

        # Cap Score
        risk_score = min(risk_score, RISK_SCORE_CAP)

        return {
            "first_seen": first_seen_str,
            "last_seen": last_seen_str,
            "duration": round(duration, 2),
            "total_attempts": total_attempts,
            "unique_usernames": list(usernames),
            "unique_passwords": list(passwords),
            "patterns": patterns,
            "risk_score": risk_score,
            "score_details": score_details,
            "events": sorted_events
        }

    def generate_report(self):
        """
        Outputs behavior_report.json with profiles for each IP.
        """
        logs = self.load_logs()
        if not logs:
            logger.warning("No logs to analyze.")
            return

        grouped = self.group_by_ip(logs)
        report = {}

        for ip, events in grouped.items():
            analysis = self.analyze_session(ip, events)
            if analysis:
                report[ip] = analysis

        try:
            with open(REPORT_FILE, 'w') as f:
                json.dump(report, f, indent=4)
            logger.info(f"Report generated: {REPORT_FILE}")
        except Exception as e:
            logger.error(f"Failed to write report: {e}")

if __name__ == "__main__":
    analyzer = LogAnalyzer()
    analyzer.generate_report()
