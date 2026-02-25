# Raspberry Pi Simulation & Testing Guide

This guide explains how to deploy your Distributed SSH Honeypot system onto a Raspberry Pi and step-by-step instructions on how to test every stage of the project.

## Part 1: Initial Setup on the Raspberry Pi

To run the simulation, your Raspberry Pi will act as the "Edge Node" running the honeypot sensor, and optionally the "Central Controller" as well.

### 1. Prerequisites
Ensure your Raspberry Pi is connected to the internet and running **Raspberry Pi OS**. You will need to install Docker and Python dependencies:
```bash
# Install Docker
curl -sSL https://get.docker.com | sh
sudo usermod -aG docker pi

# Install Python dependencies (for running local tests)
sudo apt update
sudo apt install python3-pip -y
pip3 install paramiko requests flask
```

### 2. Transfer Project Files
Copy the entire `dsrt` project folder to your Raspberry Pi using SCP or a USB drive.
```bash
scp -r "C:\Users\alexh\OneDrive\Desktop\dsrt" pi@<RASPBERRY_PI_IP>:~/dsrt
```

### 3. Start the Distributed System (Stage 4, 6)
The easiest way to run the full distributed system (Controller + Honeypot) is through Docker Compose.
```bash
cd ~/dsrt
docker-compose up --build -d
```
This command starts both the `controller` (port 5000) and the `honeypot` (port 2222) in the background.

---

## Part 2: Testing Every Stage

You can test the components individually or run the full system validation. Open a terminal on your PC or directly on the Raspberry Pi and navigate to the project folder (`cd ~/dsrt`).

> [!NOTE]
> If testing Stage 2 (LLM Integration), assure you have Ollama running locally at `http://localhost:11434` with the `llama3` model, or modify `llm_interface.py` to point to a remote LLM API.

### Stage 1: Behavioral Analysis
Tests the `analyzer.py` module to ensure it can parse logs, detect brute-force/credential-stuffing patterns, and calculate risk scores.
```bash
python3 test_stage1.py
```

### Stage 2: LLM Integration
Validates that your honeypot can format attacker profiles into LLM prompts and successfully parse JSON responses from Ollama.
```bash
python3 test_stage2.py
```

### Stage 3: Active Deception
Tests the `FakeFilesystem` and `CommandSimulator`. It verifies that when an attacker logs in, they get fake files (`/etc/passwd`) and simulated commands (`ls`, `whoami`).
```bash
python3 test_stage3.py
```

### Stage 4 & 5: Distributed Architecture & Metrics
While Stage 4 is demonstrated by running `docker-compose up`, you can test the analytics and metric generation (`metrics.py`):
```bash
python3 test_stage5.py
```
This generates mock logs and tests the output of `experiment_metrics.json` and `analysis_report.md`.

### Stage 6: Autonomous Orchestration
Tests if the local honeypot correctly pulls global blocklists from the controller.
```bash
python3 test_stage6.py
```

### Stage 7: Final Validation (End-to-End simulation)
This robust validation script launches its own local Controller and Honeypot temporarily to run a full simulation. It performs connection brute-forcing, validates that the IP gets blocked globally, logs into the deceptive shell, interacts with it, and generates the final reports.

> [!IMPORTANT]
> Since this script launches its own server instances, stop Docker before running this command if you started it earlier (`docker-compose down`).

```bash
python3 validate_system.py
```

### Extreme Stress Testing
If you want to simulate a massive botnet attack on the honeypot:
```bash
python3 stress_test_final.py
```
This will flood the server with rapid concurrent connections to benchmark queue handling and thread safety.
