# AI-Driven SIEM

A single-host security-monitoring prototype that brings system metrics, network metadata,
event logs, and AI-assisted analysis into a web dashboard.

> This is an academic prototype, not a production or enterprise SIEM. It does not collect
> telemetry from remote hosts or automatically block threats.

## Project at a glance

The application collects CPU, memory, and disk metrics with `psutil` and optional GPU
information with `GPUtil`. Scapy captures IPv4 TCP/UDP packet metadata visible to the app.
The Flask backend stores records in SQLite and serves a dashboard with live updates,
network/log tables, and an AI chat panel.

```text
Host metrics ─┐
              ├─> Flask + Socket.IO ─> SQLite ─> Browser dashboard
Packet metadata┘          ├─> Groq API (chat and analysis)
                          └─> Ollama (local AI notifications)
```

### Main technologies

- **Backend:** Python, Flask, Flask-SocketIO
- **Monitoring/capture:** psutil, GPUtil, Scapy
- **Storage:** SQLite
- **AI:** Groq API, Ollama, TensorFlow/Keras, Hugging Face Hub
- **Frontend:** HTML/Jinja, Tailwind CSS, Chart.js, Socket.IO
- **Deployment:** Docker Compose, Jenkins, GitHub

## Run the application with Docker

Prerequisites: Docker Desktop with Linux containers and Docker Compose.

1. In PowerShell, from the project directory:

   ```powershell
   Copy-Item .env.example .env
   notepad .env
   ```

2. Set `GROQ_API_KEY` to your own Groq API key and `FLASK_SECRET_KEY` to a private random
   value. `HF_TOKEN` is optional for the public model. Never commit or share `.env`.

   Generate a Flask secret locally:

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. Build and start the services:

   ```powershell
   docker compose up --build -d
   docker compose ps
   ```

   First startup may take several minutes: Docker downloads application dependencies and
   the Ollama `llama3.2` model.

4. Open the app:

   - Create an account: <http://localhost:5000/register>
   - Sign in: <http://localhost:5000/login>
   - Dashboard: <http://localhost:5000/>

   There is no default username or password.

Useful commands:

```powershell
docker compose logs -f siem
docker compose ps
docker compose down
```

`docker compose down` preserves named volumes. Avoid `docker compose down --volumes` unless
you intend to remove the SQLite data, Ollama model, and Jenkins configuration.

## Jenkins

Jenkins is included in the Compose configuration and is available at
<http://localhost:8081>.

1. Retrieve the initial administrator password:

   ```powershell
   docker compose exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
   ```

2. Complete the Jenkins setup and install the Pipeline and Credentials Binding plugins.
3. Create a Pipeline job pointing at this GitHub repository, branch `*/main`, with script
   path `Jenkinsfile`.
4. Add two **Secret text** credentials in Jenkins' **System → Global** store:

   | Credential ID | Value |
   |---|---|
   | `groq-api-key` | Your Groq API key |
   | `flask-secret-key` | A long random Flask secret |

The pipeline checks out the code, validates Docker Compose, builds the SIEM image, and
deploys the stack from `main`. It does not currently run a full automated test suite.

**Jenkins security:** Jenkins can access the Docker socket, which gives it broad control
over Docker on this machine. It is bound to localhost; keep its credentials private and do
not expose Jenkins or the Docker socket to an untrusted network.

## Data and configuration

Docker Compose uses named volumes:

- `siem_data` — SQLite database at `/app/data/system_metrics.db`
- `ollama_data` — downloaded Ollama model
- `jenkins_data` — Jenkins configuration and credentials

The database contains `users`, `metrics`, `logs`, and `network_requests` tables. User
passwords are stored as hashes.
## Known limitations

- The project monitors one application environment; it is not a multi-host SIEM.
- The SecIDS-CNN model can be loaded, but **CNN classification is not connected to live
  packet processing**.
- Docker Desktop on Windows may not expose all physical-host network traffic to the
  container. Metrics in Docker may also reflect the container/VM environment rather than
  every Windows host metric.
- Groq and IP enrichment use external services. Treat logs and network information as
  sensitive.
- The app uses Flask's development server and is not hardened for public production use.
  Keep it on a trusted network and do not expose it directly to the internet.
- AI output is advisory; the app does not perform autonomous threat response.

## Troubleshooting

Check Docker Desktop and the app:

```powershell
docker desktop status
docker info
docker compose ps
docker compose logs --tail 80 siem
curl.exe -I --max-time 20 http://127.0.0.1:5000/login
```

If Docker Desktop reports a WSL startup error, resolve the Docker/WSL engine issue before
debugging the Flask app. Back up data before resetting Docker or removing volumes.
