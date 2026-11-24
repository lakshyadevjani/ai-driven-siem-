# AI-Driven SIEM Dashboard

This project provides a Flask-based SIEM dashboard for live system metrics, network packet
logging, IP reputation checks, SQLite history, Groq analysis, and local Ollama notifications.

## Features

- Protected dashboard login and registration
- Live CPU, memory, and disk metrics through Socket.IO
- Network packet capture with Scapy
- Public-IP geolocation and Blocklist.de reputation checks
- SQLite storage for metrics, logs, and network requests
- Groq chat and periodic system analysis
- Optional Ollama notifications and Docker Compose Ollama service
- Hugging Face-hosted TensorFlow CNN model loading
- Docker and Jenkins deployment support

## Requirements

- Docker Desktop or Docker Engine with Compose
- Groq API key
- Network privileges for packet capture
- Linux or Docker host networking is recommended for production packet visibility

## Local Configuration

Create a local environment file:

```powershell
Copy-Item .env.example .env
```

Set at least:

```dotenv
GROQ_API_KEY=your_groq_api_key_here
FLASK_SECRET_KEY=replace_with_a_long_random_secret
OLLAMA_BASE_URL=http://localhost:11434
HF_TOKEN=your_huggingface_token_here
```

The Hugging Face token is only needed for gated/private model repositories. It is optional
for the public model configured in `app_groq.py`.

## Run Locally

```powershell
python -m venv venv
.\\venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python app_groq.py
```

Open `http://localhost:5000`. Register the first user and log in.

## Run with Docker

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose logs -f siem
```

Open `http://localhost:5000`.

The Compose stack starts:

- `siem` on port 5000
- `ollama` on port 11434
- `ollama-init`, which downloads the `llama3.2` model
- Named volumes for SIEM data and Ollama models

## Docker Network Scope

By default, Docker networking limits packet capture to traffic visible inside the container.
For visibility into host traffic, run the SIEM container with host networking and configure
packet capture interfaces appropriately. Packet capture also requires `NET_RAW` and `NET_ADMIN`.

## Jenkins

`Jenkinsfile` defines a pipeline that:

1. Checks out the source
2. Compiles the Python files
3. Validates Docker Compose
4. Builds the image
5. Deploys with Docker Compose on `main` or `master`

The Jenkins agent must have Docker, Docker Compose, and access to `.env`. Provide the Groq,
Hugging Face, and Flask secret values through Jenkins credentials or a protected environment
file rather than committing them.

## Database

SQLite data is stored in `/app/data/system_metrics.db` inside the container. Named Docker
volumes preserve that data across container restarts.

Tables include:

- `users`
- `logs`
- `metrics`
- `network_requests`

## Security

- Passwords use Werkzeug password hashing.
- Dashboard and data APIs require a logged-in session.
- Socket.IO connections require an authenticated Flask session.
- Set `FLASK_SECRET_KEY` to a stable random value in production.
- Run the application behind HTTPS in a public deployment.
- Restrict packet-sniffing and SIEM network access to authorized users.
