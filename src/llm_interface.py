import requests
import json
import logging
import time

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LLMInterface:
    """
    Connects to a local LLM API (Ollama) to analyze attacker profiles and enrich behavior reports.
    """

    def __init__(self, model_name="llama3", api_url="http://localhost:11434/api/generate", timeout=30, max_retry=2):
        """
        Initialize LLMInterface.
        
        Args:
            model_name (str): Name of the Ollama model (default: llama3).
            api_url (str): URL of the Ollama generate API.
            timeout (int): Request timeout in seconds.
            max_retry (int): Number of retries for failed requests.
        """
        self.model_name = model_name
        self.api_url = api_url
        self.timeout = timeout
        self.max_retry = max_retry

    def check_availability(self):
        """
        Ping the Ollama API to confirm it is running.
        
        Returns:
            bool: True if available, False otherwise.
        """
        try:
            # Pittle hack: generate empty prompt or version check
            # Better check: GET /api/tags or just a quick generate
            response = requests.post(self.api_url, json={
                "model": self.model_name,
                "prompt": "hi",
                "stream": False
            }, timeout=5)
            if response.status_code == 200:
                logger.info(f"Ollama API available: {self.api_url}")
                return True
            else:
                logger.error(f"Ollama API returned status: {response.status_code}")
                return False
        except requests.RequestException as e:
            logger.error(f"Ollama API unavailable: {e}")
            return False

    def generate_prompt(self, ip, profile):
        """
        Constructs a prompt for the LLM using a single IP's profile.
        
        Args:
            ip (str): Attacker IP address.
            profile (dict): Attacker profile from Stage 1.
            
        Returns:
            str: The constructed prompt.
        """
        # Simplify profile for prompt to save tokens/noise
        summary_profile = {
            "total_attempts": profile.get("total_attempts"),
            "duration": profile.get("duration"),
            "unique_usernames": profile.get("unique_usernames"),
            "unique_passwords": profile.get("unique_passwords"),
            "patterns": profile.get("patterns"),
            "risk_score": profile.get("risk_score")
        }
        
        prompt = f"""
You are a cybersecurity analyst. Analyze this SSH honeypot attacker profile for IP {ip}.

Attacker Profile:
{json.dumps(summary_profile, indent=2)}

Analysis Requirements:
1. Determine the likely **intent** (e.g., 'reconnaissance', 'credential_stuffing', 'brute_force', 'automated_bot').
2. Assess **sophistication** (low, medium, high).
3. Suggest a **recommended_action** (block, deceive, observe).
4. Provide a brief **summary** of the behavior.

Output strictly valid JSON with keys: "intent", "sophistication", "recommended_action", "summary".
Do not include markdown formatting or explanations outside the JSON.
"""
        return prompt

    def send_request(self, prompt, num_predict=150):
        """
        Send the prompt to the LLM API with retries.
        
        Returns:
            str: Raw response text or None if failed.
        """
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json", # Force JSON mode if supported by model/ollama version
            "keep_alive": -1,  # Prevent model from unloading from VRAM after 5 minutes
            "options": {
                "num_predict": num_predict, # Restrict generation ceiling to speed up output
                "temperature": 0.1 # Low temp for fastest deterministic output
            }
        }
        
        for attempt in range(self.max_retry + 1):
            try:
                # logger.info(f"Sending request to LLM (Attempt {attempt+1})...")
                start_time = time.time()
                response = requests.post(self.api_url, json=payload, timeout=self.timeout)
                response.raise_for_status()
                latency = time.time() - start_time
                logger.info(f"LLM Inference completed in {latency:.2f}s")
                return response.json().get("response", "")
            except requests.RequestException as e:
                logger.warning(f"LLM request failed: {e}")
                time.sleep(1)
        
        logger.error("Max retries exceeded for LLM request.")
        return None

    def parse_response(self, raw_response):
        """
        Parse the LLM response into a Python dictionary.
        
        Returns:
            dict: Parsed analysis or fallback default.
        """
        fallback = {
            "intent": "unknown",
            "sophistication": "unknown",
            "recommended_action": "observe",
            "summary": "LLM analysis failed."
        }
        
        if not raw_response:
            return fallback

        try:
            # Clean up potential markdown code blocks
            clean_response = raw_response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.startswith("```"): # Sometimes just ```
                clean_response = clean_response[3:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            
            clean_response = clean_response.strip()
            
            data = json.loads(clean_response)
            
            # loose validation
            required_keys = ["intent", "sophistication", "recommended_action", "summary"]
            for key in required_keys:
                if key not in data:
                    data[key] = "unknown"
            
            return data
        except json.JSONDecodeError:
            logger.error(f"Failed to parse LLM JSON: {raw_response[:100]}...")
            return fallback

    def analyze_attacker(self, ip, profile):
        """
        Main function to analyze an attacker.
        
        Returns:
            dict: Enriched attacker profile.
        """
        prompt = self.generate_prompt(ip, profile)
        # Profile analysis takes longer, allow higher output limits
        raw_response = self.send_request(prompt, num_predict=250)
        analysis = self.parse_response(raw_response)
        
        # Merge analysis into profile
        profile.update(analysis)
        return profile

    def generate_command_prompt(self, ip, command, history, filesystem_context):
        """
        Constructs a prompt for evaluating a real-time shell command.
        
        Args:
            ip (str): Attacker IP address.
            command (str): Current shell command.
            history (list): List of previous commands in the session.
            filesystem_context (dict): Current directory and its contents.
            
        Returns:
            str: The constructed prompt.
        """
        # OPTIMIZATION: Drastically cut token count to reduce inference latency 
        # Only sending the last 3 history commands to save parsing time.
        recent_history = history[-3:] if history else []
        
        prompt = f"""
Evaluate command for SSH Honeypot.
Cmd: {command}
Hist: {json.dumps(recent_history)}
Dir: {filesystem_context.get('path', '/')}
Action rules: ALLOW recon (ls, pwd). BLOCK destructive (rm, wget).
If ALLOW, optionally provide decoy file.
Respond ONLY in this JSON format:
{{"action":"ALLOW"|"BLOCK","reason":"short","risk_score":50,"dynamic_decoy":{{"should_deploy":true|false,"path":"/dir/file","content":"fake data"}}}}
"""
        return prompt

    def evaluate_command(self, ip, command, history, filesystem_context):
        """
        Evaluates a real-time command and returns an action/decoy decision.
        """
        prompt = self.generate_command_prompt(ip, command, history, filesystem_context)
        # Pass a strict token limit since we only expect a tiny JSON dictionary for command evaluations
        raw_response = self.send_request(prompt, num_predict=80) 
        
        fallback = {
            "action": "ALLOW",
            "reason": "LLM Failure - Fail Open",
            "risk_score": 0,
            "dynamic_decoy": {
                "should_deploy": False,
                "path": "",
                "content": ""
            }
        }
        
        if not raw_response:
            return fallback

        try:
            clean_response = raw_response.strip()
            if clean_response.startswith("```json"):
                clean_response = clean_response[7:]
            if clean_response.startswith("```"):
                clean_response = clean_response[3:]
            if clean_response.endswith("```"):
                clean_response = clean_response[:-3]
            
            clean_response = clean_response.strip()
            data = json.loads(clean_response)
            
            if "action" not in data or data["action"] not in ["ALLOW", "BLOCK"]:
                data["action"] = "ALLOW"
                
            if "dynamic_decoy" not in data:
                data["dynamic_decoy"] = fallback["dynamic_decoy"]
                
            return data
        except json.JSONDecodeError:
            logger.error(f"Failed to parse LLM command evaluation JSON: {raw_response[:100]}...")
            return fallback

