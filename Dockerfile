FROM python:3.9-slim

WORKDIR /app

# Install dependencies
RUN pip install paramiko requests flask flask-cors

# Copy source files from src/ folder
COPY src/honeypot.py .
COPY src/deception.py .
COPY src/controller_server.py .
COPY src/llm_interface.py .
COPY src/analyzer.py .
COPY src/metrics.py .
COPY src/brain_server.py .
COPY src/decoy_templates.json .
# Host key should ideally be generated or mounted, but copying for simplicity in dev
COPY host.key .

# Environment setup
ENV PYTHONUNBUFFERED=1
ENV HOST_KEY_PATH=/app/host.key

# Expose ports (2222 for honeypot, 5000 for controller if running combined image)
EXPOSE 2222
EXPOSE 5000

CMD ["python", "honeypot.py"]
