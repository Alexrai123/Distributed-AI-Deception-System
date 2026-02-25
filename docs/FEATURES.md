# HoneyPot AI: Distributed SSH Honeypot System Features

This document provides a comprehensive overview of all features implemented in the Distributed SSH Honeypot System, broken down by architectural stages.

## Operational Modes
- **Mode 1: Low-Interaction (Brute-Force Defense):** The honeypot aggressively enforces its password policy (`ALLOW_ALL_CREDS = False`). It logs username/password combinations, rejects all logins, and instantly drops TCP connections from IPs that trigger the 5-attempt strike limit. This is ideal for studying automated botnet guessing behavior and securing the network perimeter.
- **Mode 2: High-Interaction (Active Deception):** The honeypot intentionally bypasses standard authentication (`ALLOW_ALL_CREDS = True`), enthusiastically accepting ANY username/password combination to lure the attacker inside. The IP auto-blocking logic is temporarily suspended to gather rich, interactive shell telemetry. This is ideal for studying human hacker techniques and payload delivery in a simulated environment.
- **Mode 3: Hybrid (Targeted Deception):** When running in `Mode 1`, the honeypot still actively listens for specific "Bait Credentials" (e.g., `admin`/`admin` or `root`/`1234`). If a sophisticated attacker or script attempts these exact high-value combinations, the system dynamically drops the blocklist logic and silently allows them into the high-interaction fake shell.

## Stage 0: Infrastructure Base (`honeypot.py`)
- **Interactive SSH Server**: A robust, local SSH honeypot (configurable port, default 2222) built using `paramiko`.
- **Credential Harvesting**: Actively captures and logs usernames and passwords from all login attempts.
- **Strict Resource Management**: Defensive connection handling with configured limits on simultaneous connections (max 50) and bounds on session durations (max 60s per connection).
- **Dynamic IP Blocking**: Blocks attacker IPs dynamically at the edge after failed login attempts cross predetermined thresholds (when operating in Low-Interaction mode).
- **Thread-safe Logging**: Asynchronous logging of security events to `honeypot_logs.json` via a scalable producer-consumer queue infrastructure.

## Stage 1: Behavioral Analysis (`analyzer.py`)
- **Attacker Profiling**: Transforms raw login logs into deep behavioral insights and profiles, grouping telemetry by source IP.
- **Pattern Recognition Mechanisms**: Accurately detects specific attack vectors such as:
  - *Credential Stuffing* (many unique passwords, few users)
  - *Brute Force* (many unique users or passwords over short times)
  - *High Velocity Attempts* 
  - *Admin/Root Targeting*
- **Risk Scoring Engine**: Dynamically calculates a risk score (0-100) per session based on payload volume and detected behavioral patterns.
- **Structured JSON Reporting**: Automatically outputs parsed JSON summaries (`behavior_report.json`) representing all attacker sessions for offline review.

## Stage 2: LLM Integration (`llm_interface.py`)
- **Semantic Machine Intelligence**: Connects to locally hosted LLMs (e.g., Llama 3 via Ollama) to analyze the systemic context behind activities.
- **Intent Classification Pipeline**: Evaluates summarized behavior profiles through LLM prompts specifically designed to categorize attacker intent (reconnaissance vs. automated bot vs. targeted strike).
- **Sophistication Assessment Classifier**: Applies heuristic-driven models to determine the overall capability and technical sophistication of the attacker footprints.
- **Context-Aware Defenses**: Automatically generates remediation suggestions (e.g., recommend "block", "deceive", or "observe" actions).

## Stage 3: Active Deception (`deception.py`)
- **Simulated Virtual Filesystem**: Hosts an interactive virtual `FakeFilesystem` containing convincingly constructed static directories (`/bin`, `/etc`, `/var`, `/tmp`).
- **Command Simulator Module**: Intercepts and replicates results for common Linux terminal shell commands (`ls`, `cd`, `pwd`, `cat`, `whoami`, `uname`, `id`) enabling attackers to "interact" realistically.
- **Dwell Time Optimization Strategies**: Enhances intelligence gathering operations by keeping connected attackers engaged within a continuously monitored trap safely disconnected from actual host functions.
- **Real-time Decoy Injection**: Has the framework to dynamically deploy fake OS configurations like dummy `/etc/passwd` tables based on requests.

## Stage 4: Distributed Architecture (`controller_server.py`, `docker-compose.yml`)
- **Central Orchestration API Node**: A robust Flask-driven command controller running on port 5000 that aggregates remote event logs globally and dictates wide networking decisions.
- **Containerized Edge Deployment**: Honeypots packaged gracefully for distributed microservice deployments—fully containerized via Docker and primed for lightweight hosts.
- **Secure Telemetry Communications**: API Key and token-authenticated remote logging endpoints securely channeling data from sensors.
- **Global Wide-Area Intelligence Sync**: Edge containers iteratively pull from the central controller to ingest the latest dynamically aggregated threat blocklists.
- **Manual Ban Overrides**: Integrated administrative endpoints (i.e., `/unblock/<ip>`) cleanly removing permanent global bans triggered during behavioral analysis or testing.

## Stage 5: Monitoring & Experimental Metrics (`metrics.py`)
- **Dwell Time Operational Analytics**: Computes deep engagement durations reflecting how effectively decoys manage to snare real users versus automated scrapers.
- **Response Efficiency Checks**: Specifically calculates performance metrics like automated block speeds (First Attempt -> Instant Block) and granular tracking of command interactions initiated under deception algorithms.
- **Systematic Global Reporting**: Funnels insights into comprehensive files (`experiment_metrics.json`) and generates formatted markdown digests (`analysis_report.md`).

## Stage 6: Autonomous Orchestration
- **Self-Managed Security Posture**: Integrates autonomous polling scripts (i.e. `BlocklistSyncer` thread) empowering the local edge network to pull blocks generated globally rather than strictly from their local dataset.
- **Intervention-free Operation**: Actively responds and manages network firewalls (or logical IP drops inside the Paramiko server) without direct human instruction or periodic offline analysis.

## Stage 7: Component Stress Validation
- **Extensive Test Coverage Suite**: Targeted sub-module `test_stageX.py` capabilities continuously assessing unit functions.
- **Parallel Emulated Load Drivers**: Robust stress test simulators (`stress_test.py`, `stress_test_final.py`) validating producer/consumer concurrency, queue handling margins, and system endurance thresholds.
- **Consolidated System Validation Executable**: A dedicated payload delivery engine (`validate_system.py`) proving systematic integration works harmoniously up the pipeline—from honeypot capture all the way to LLM response routing.

## Stage 8: Real-Time AI Brain Server
- **Split-Architecture Execution**: Physically separates the network frontline sensors (Raspberry Pi Edge Nodes) from the heavy AI computational processing (Windows PC Brain Server).
- **Asynchronous LLM Proxy (`brain_server.py`)**: A permanent, un-containerized Flask server running on the command center that securely interfaces with local High-VRAM AI models (e.g., Llama 3 via Ollama) without exposing the model directly to the open web.
- **Dynamic Policy Enforcement**: The Raspberry Pi Controller automatically fires raw session telemetry to the Brain Server upon an attacker's disconnection (`SHELL_SESSION_END`). The Brain Server mathematically evaluates the intent and returns a structured JSON recommendation (e.g., `deceive` or `block`) which the Raspberry Pi immediately enforces across the global blocklist.
