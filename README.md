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

Start the local Jenkins controller with:

```powershell
docker compose up --build -d jenkins
docker compose logs jenkins
```

Open `http://localhost:8081`. Retrieve the initial administrator password with:

```powershell
docker compose exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

Complete the setup wizard and install the suggested plugins, including Pipeline and
Credentials Binding. Create a Pipeline job configured to use this Git repository, branch
`main`, and script path `Jenkinsfile`. For a private repository, configure a GitHub access
credential in Jenkins.

Add these Jenkins **Secret text** credentials using the exact IDs:

- `groq-api-key` — a valid Groq API key
- `flask-secret-key` — a long, random Flask session secret

The pipeline checks out the source, validates Compose, builds the SIEM image, then deploys
on `main`. It writes a temporary `.env` from Jenkins credentials and removes it afterward;
secrets are not stored in Git. The public Hugging Face model does not require a token.

The Jenkins container mounts the Docker socket so it can build and deploy containers. Access
to that socket grants control over the Docker host. Jenkins is therefore bound to localhost
only; do not expose port 8080 or the Docker socket to an untrusted network. Keep Jenkins
credentials and the Jenkins administrator account private.

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
