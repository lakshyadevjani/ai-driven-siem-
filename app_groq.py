from flask import Flask, jsonify, request, render_template
from flask import redirect, session, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash
import tensorflow as tf
import numpy as np
import psutil
import datetime
import sqlite3
from ollama_lib import OllamaClient
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import ipaddress
import threading
import requests
import re
import os
from collections import deque
from functools import wraps
# removed unused transformers import
import GPUtil
from huggingface_hub import hf_hub_download
from flask_socketio import SocketIO, emit
import time

from dotenv import load_dotenv

# Load variables from a local .env file (never commit this file)
load_dotenv()

# Groq API Key und Header
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise RuntimeError(
        "GROQ_API_KEY is not set. Create a .env file (see .env.example) "
        "and add GROQ_API_KEY=your_key_here."
    )
GROQ_HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
socketio = SocketIO(app, async_mode="threading")


# Load or download the model from Hugging Face if not already present
DATA_DIR = os.environ.get('DATA_DIR', '.')
MODEL_PATH = os.path.join(DATA_DIR, 'SecIDS-CNN.h5')
MODEL_ID = "Keyven/SecIDS-CNN"
FILENAME = "SecIDS-CNN.h5"

# Optional: only needed if the model repo is private/gated
HF_TOKEN = os.environ.get("HF_TOKEN")

# Check whether the model is already available locally
if not os.path.exists(MODEL_PATH):
    print("Downloading model from Hugging Face...")
    try:
        # Download the model file from the Hugging Face Hub
        model_file = hf_hub_download(repo_id=MODEL_ID, filename=FILENAME, token=(HF_TOKEN or None))
        # Load the model with TensorFlow/Keras
        model = tf.keras.models.load_model(model_file)
        # Save the model locally for future use
        model.save(MODEL_PATH)
        print("Model successfully downloaded and saved.")
    except Exception as e:
        print(f"Error downloading the model: {e}")
else:
    print("Loading model from local storage...")
    model = tf.keras.models.load_model(MODEL_PATH)
    print("Model successfully loaded from local storage.")

# Ollama Client initialisieren
ollama_client = OllamaClient(
    base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
)

# Database connection
def get_db_connection():
    conn = sqlite3.connect(os.path.join(DATA_DIR, 'system_metrics.db'), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database tables
def initialize_database():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        # Table for network requests
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                type TEXT,
                country TEXT,
                summary TEXT,
                blacklisted TEXT,
                attacks INTEGER,
                reports INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_network_requests_timestamp ON network_requests (timestamp);
        """)
        # Table for logs
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log TEXT
            );
        """)
        # Index for logs
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp);
        """)
        # Table for system metrics (if not already present)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu REAL,
                memory REAL,
                disk REAL,
                network INTEGER
            );
        """)
        # Index for metrics
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);
        """)
        conn.commit()

# Initialize the database on application startup
initialize_database()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api") or request.path in {
                "/chat", "/logs", "/search-logs", "/network-requests",
                "/system-info", "/server-status"
            }:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login", next=request.full_path))
        return view(*args, **kwargs)
    return wrapped

# WHOIS lookup function for IPv4 addresses only; local and IPv6 addresses are skipped
def get_ip_country(ip):
    try:
        if ":" in ip or ipaddress.ip_address(ip).is_private:
            return "Not checkable"
        
        response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        country = response.get("country_name", "Unbekannt")
        city = response.get("city", "Unbekannt")
        state = response.get("state", "Unbekannt")
        return f"{country}, {city}, {state}"
    except (requests.RequestException, ValueError):
        return "Error"

# Use a deque for network requests with a bounded size (optional, if still used)
MAX_NETWORK_REQUESTS = 1000
network_requests = deque(maxlen=MAX_NETWORK_REQUESTS)

# Function for system information and hardware data
@app.route('/system-info', methods=['GET'])
@login_required
def system_info():
    try:
        # CPU Informationen
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'
        cpu_cores = psutil.cpu_count(logical=False)
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory().total
        disk = psutil.disk_usage('/').total

        # GPU Informationen mit GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            gpu_usage = f"{gpus[0].load * 100:.2f}%"
            gpu_memory_used = f"{gpus[0].memoryUsed} MB"
            gpu_memory_total = f"{gpus[0].memoryTotal} MB"
        else:
            gpu_usage = "N/A"
            gpu_memory_used = "N/A"
            gpu_memory_total = "N/A"

        # Power information (for laptops)
        battery = psutil.sensors_battery()
        power_usage = battery.percent if battery else 'N/A'

        # Assemble the JSON response
        system_info_data = {
            "cpu_frequency": cpu_freq,
            "cpu_cores": cpu_cores,
            "cpu_usage": cpu_usage,
            "gpu_usage": gpu_usage,
            "gpu_memory_used": gpu_memory_used,
            "gpu_memory_total": gpu_memory_total,
            "power_usage": power_usage,
            "memory_total": memory,
            "disk_total": disk
        }

        # Debug-Ausgabe in der Konsole
        print("System Info:", system_info_data)

        return jsonify(system_info_data)

    except Exception as e:
        print("Error fetching system information:", e)
        return jsonify({"error": "Error fetching system information"}), 500

# Use the CNN model for network packet analysis
def analyze_packet_with_cnn(packet_data):
    prediction = model.predict(np.array([packet_data]))[0]
    return "suspicious" if prediction[1] > 0.5 else "normal"

# Function that periodically sends system metrics, logs, and network packets to the frontend client and Groq
def send_system_metrics():
    while True:
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent

        # Send the metrics to the client via WebSocket
        socketio.emit('update_metrics', {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'cpu_frequency': psutil.cpu_freq().current,
            'cpu_cores': psutil.cpu_count(),
            'gpu_usage': 'N/A',  # Placeholder, in case GPU info is needed
            'gpu_memory_used': 'N/A',
            'gpu_memory_total': 'N/A',
            'power_usage': 'N/A',
            'memory_total': psutil.virtual_memory().total,
            'disk_total': psutil.disk_usage('/').total
        })

        # Collect network packets and logs
        logs = fetch_recent_logs()
        network_data = fetch_recent_network_data()

        # Groq API request
        payload = {
            "model": "llama-3.1-8b-instant",  # The model can be adjusted here
            "messages": [
                {"role": "system", "content": f"Systemmetriken: CPU: {cpu_usage}%, RAM: {memory_usage}%, Festplatte: {disk_usage}%."},
                {"role": "user", "content": f"Logs: {logs}, Network: {network_data}"}
            ]
        }

        try:
            # Groq API request
            response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=GROQ_HEADERS, json=payload)
            response_data = response.json()
            assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "No response")
            save_log(f"AI response: {assistant_message}")
        except requests.RequestException as e:
            print(f"Error requesting Groq: {e}")

        time.sleep(5)  # Alle 5 Sekunden

# Function to fetch recent logs
def fetch_recent_logs():
    with get_db_connection() as conn:
        logs = conn.execute("SELECT log FROM logs ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [log["log"] for log in logs]

# Function to fetch recent network data
def fetch_recent_network_data():
    with get_db_connection() as conn:
        network_data = conn.execute("SELECT ip, country, summary FROM network_requests ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [{"ip": request["ip"], "country": request["country"], "summary": request["summary"]} for request in network_data]


# WebSocket-Handler, der bei jeder Verbindung gestartet wird
@socketio.on('connect')
def handle_connect():
    if not session.get("user_id"):
        return False
    print("Client connected")
    socketio.start_background_task(send_system_metrics)  # Start the background task for metrics

# WebSocket handler for sending logs
@socketio.on('new_log')
def handle_new_log(log_data):
    socketio.emit('new_log', log_data)  # Sende das neue Log an den Client

# WebSocket handler for network packets
@socketio.on('new_network_request')
def handle_new_network_request(network_data):
    socketio.emit('new_network_request', network_data)  # Send the network request to the client


# Network packet callback using the CNN model for security analysis
# Updated `packet_callback` function that uses cached blacklist checks
def packet_callback(packet):
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        ip = packet[IP].src
        summary = packet.summary()

        # Check whether the IP is local, IPv6, or excluded
        excluded_ips = {"144.76.114.3", "159.89.102.253"}
        if ip in excluded_ips or ipaddress.ip_address(ip).is_private or ":" in ip:
            country = "Local/IPv6 or excluded"
            is_blacklisted = False
            attacks = 0
            reports = 0
        else:
            country = get_ip_country(ip)
            blacklist_status = check_ip_blacklist_cached(ip)
            is_blacklisted = blacklist_status["blacklisted"]
            attacks = blacklist_status.get("attacks", 0)
            reports = blacklist_status.get("reports", 0)
        
        # Database entry for network packets
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO network_requests (ip, type, country, summary, blacklisted, attacks, reports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip, "IPv4", country, summary, "Ja" if is_blacklisted else "Nein", attacks, reports))
            conn.commit()

        # Loggen und ggf. Benachrichtigung
        log_message = f"Network packet from {ip} ({country}) - Blacklisted: {is_blacklisted}"
        save_log(log_message)
        socketio.emit('new_network_request', {
            "ip": ip,
            "country": country,
            "summary": summary,
            "blacklisted": "Ja" if is_blacklisted else "Nein",
            "attacks": attacks
        })
        if is_blacklisted:
            notify_ai(log_message)


# Pagination and searching older logs
@app.route('/logs', methods=['GET'])
@login_required
def get_logs():
    page = int(request.args.get('page', 1))
    page_size = 50
    offset = (page - 1) * page_size
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log 
            FROM logs 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        """, (page_size, offset)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"]} for log in logs])

# Logs nach bestimmten Kriterien durchsuchen
@app.route('/search-logs', methods=['POST'])
@login_required
def search_logs():
    search_term = request.json.get('query', '')
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log 
            FROM logs 
            WHERE log LIKE ? 
            ORDER BY timestamp DESC
        """, ('%' + search_term + '%',)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"]} for log in logs])

# Metriken und Logs speichern
def save_metrics(cpu, memory, disk, network):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO metrics (timestamp, cpu, memory, disk, network) 
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cpu, memory, disk, network))
        conn.commit()

def save_log(log):
    with get_db_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO logs (timestamp, log) 
            VALUES (?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), log))
        conn.commit()
    socketio.emit('new_log', {
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "log": log
    })

# AI notification for suspicious activity (short answers directly in the prompt)
def notify_ai(message):
    short_prompt = f"{message}\nPlease answer briefly and concisely, max 1-2 sentences."
    try:
        response = ollama_client.chat(model="llama3.2", messages=[{"role": "user", "content": short_prompt}])
        response = response.get("choices", [{}])[0].get("message", {}).get("content", "No response")
    except Exception as e:
        response = f"Ollama unavailable: {e}"
    save_log(f"AI notification: {response}")

# Regularly analyze system metrics
def analyze_metrics(cpu, memory, disk):
    if cpu > 85 or memory > 80 or disk > 90:
        message = f"Warning: High system load - CPU: {cpu}%, RAM: {memory}%, Disk: {disk}%."
        notify_ai(message)

# Startseite
@app.route('/')
@login_required
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == 'POST':
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            next_url = request.args.get("next")
            return redirect(next_url if next_url and next_url.startswith("/") else url_for("home"))

        flash("Invalid username or password.", "danger")

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == 'POST':
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        else:
            try:
                with get_db_connection() as conn:
                    conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, generate_password_hash(password))
                    )
                    conn.commit()
            except sqlite3.IntegrityError:
                flash("Username is already registered.", "danger")
            else:
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))

    return render_template('register.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route('/get_recent_logs', methods=['GET'])
@login_required
def get_recent_logs():
    with get_db_connection() as conn:
        logs = conn.execute(
            "SELECT log, timestamp FROM logs ORDER BY timestamp DESC LIMIT 20"
        ).fetchall()
    return jsonify([
        {"source": "System", "message": log["log"], "severity": "Info",
         "timestamp": log["timestamp"]}
        for log in logs
    ])

# Server-Status
@app.route('/server-status', methods=['GET'])
@login_required
def server_status():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    print(f"CPU: {cpu}, Memory: {memory}, Disk: {disk}")
    
    save_metrics(cpu, memory, disk, 0)
    analyze_metrics(cpu, memory, disk)
    
    return jsonify({
        "cpu_usage": cpu,
        "memory_usage": memory,
        "disk_usage": disk
    })

# Cached blacklist check
def check_ip_blacklist_cached(ip):
    with get_db_connection() as conn:
        result = conn.execute("SELECT blacklisted, attacks, reports FROM network_requests WHERE ip = ?", (ip,)).fetchone()
        if result:
            # IP already checked
            return {
                "blacklisted": result["blacklisted"] == "Ja",
                "attacks": result["attacks"],
                "reports": result["reports"]
            }
        
        # API request if the IP is not in the database
        url = f"http://api.blocklist.de/api.php?ip={ip}&format=json"
        try:
            response = requests.get(url)
            data = response.json() if response.status_code == 200 else {"blacklisted": False}
            blacklisted = data.get("attacks", 0) > 0
            attacks = data.get("attacks", 0)
            reports = data.get("reports", 0)
            
            # Save to the database
            conn.execute(
                "INSERT INTO network_requests (ip, blacklisted, attacks, reports) VALUES (?, ?, ?, ?)",
                (ip, "Ja" if blacklisted else "Nein", attacks, reports)
            )
            conn.commit()

            return {"blacklisted": blacklisted, "attacks": attacks, "reports": reports}
        except requests.RequestException:
            return {"blacklisted": False}

# IP aus Nachricht extrahieren
def extract_ip_from_message(message):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, message)
    return match.group(0) if match else None

# Funktion zur Initialisierung des Groq-Clients
def initialize_groq_client():
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }
    return headers

# Funktion zur Integration der Groq-Chat-Funktion
@app.route('/chat', methods=['POST'])
@login_required
def chat_with_groq():
    data = request.get_json()
    user_message = data.get('message', '')

    # Systemmetriken abrufen
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent

    # Collect logs and network packets
    logs = fetch_recent_logs()
    network_data = fetch_recent_network_data()

    context_message = (
        f"{user_message}\n"
        f"System metrics: CPU: {cpu}%, Memory: {memory}%, Disk: {disk}%.\n"
        f"Logs: {logs}, Network: {network_data}\n"
        "Please answer briefly and concisely."
    )

    payload = {
        "model": "llama-3.1-8b-instant",  # The model can be adjusted here
        "messages": [{"role": "user", "content": context_message}]
    }

    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", headers=GROQ_HEADERS, json=payload)
        response_data = response.json()
        assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "No response")
    except requests.RequestException as e:
        print("Error requesting Groq:", e)
        assistant_message = f"Error requesting Groq: {e}"

    save_log(f"User: {user_message}, AI: {assistant_message}")
    return jsonify({"response": assistant_message})




# Fetch network requests with pagination
@app.route('/network-requests', methods=['GET'])
@login_required
def get_network_requests():
    try:
        page = int(request.args.get('page', 1))
        page_size = 50
        offset = (page - 1) * page_size
        with get_db_connection() as conn:
            requests = conn.execute("""
                SELECT ip, type, country, summary, blacklisted, attacks, reports, timestamp 
                FROM network_requests 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (page_size, offset)).fetchall()
        data = [dict(request) for request in requests]
        return jsonify(data)
    except Exception as e:
        print(f"Error fetching network requests: {e}")
        return jsonify({"error": "Error fetching network requests"}), 500


# Starten Sie das Paket-Sniffing in einem separaten Thread
def start_sniffing():
    sniff(prn=packet_callback, store=0)

if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()
    socketio.run(app, host="0.0.0.0", debug=True, port=5000, use_reloader=False, allow_unsafe_werkzeug=True)
    
