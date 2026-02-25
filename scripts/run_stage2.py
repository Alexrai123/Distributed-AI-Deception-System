import json
import logging
import os
import sys

# Add src/ to path so we can import from there
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from llm_interface import LLMInterface

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

INPUT_FILE = os.path.join(_ROOT, 'logs', 'behavior_report.json')
OUTPUT_FILE = os.path.join(_ROOT, 'logs', 'full_incident_report.json')

def main():
    if not os.path.exists(INPUT_FILE):
        logger.error(f"Input file {INPUT_FILE} not found. Run Stage 1 first.")
        return

    # Load Stage 1 Report
    try:
        with open(INPUT_FILE, 'r') as f:
            report = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load report: {e}")
        return

    # Initialize LLM
    llm = LLMInterface()
    if not llm.check_availability():
        logger.warning("Ollama not available. Proceeding with mock/fallback analysis? (No, exiting in strict mode)")
        # For this stage, we might want to exit or continue with errors.
        # Strict mode: exit.
        # return 

    enriched_report = {}
    
    logger.info(f"Starting LLM analysis for {len(report)} attackers...")
    
    for ip, profile in report.items():
        logger.info(f"Analyzing IP: {ip}")
        try:
            enriched_profile = llm.analyze_attacker(ip, profile)
            enriched_report[ip] = enriched_profile
        except Exception as e:
            logger.error(f"Error analyzing {ip}: {e}")
            enriched_report[ip] = profile # Keep original data even if LLM fails

    # Save Output
    try:
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(enriched_report, f, indent=4)
        logger.info(f"Full incident report saved to {OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Failed to save output: {e}")

if __name__ == "__main__":
    main()
