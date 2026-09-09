from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_from_directory, send_file, make_response
from flask_socketio import SocketIO
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import time
import socket
import json
import random
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'z_data_network_ULTRA_SECRET_KEY_2024_NEVER_SHARE'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)

# --- Sécurité avancée : Limiter les tentatives de connexion ---
login_attempts = {}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Veuillez vous connecter.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_rate_limit(ip):
    """Empêche les attaques par force brute (5 tentatives max)"""
    if ip in login_attempts:
        attempts, last_time = login_attempts[ip]
        if attempts >= 5 and (time.time() - last_time) < 300:
            return False
        return True
    return True

def register_attempt(ip):
    if ip in login_attempts:
        attempts, last_time = login_attempts[ip]
        login_attempts[ip] = (attempts + 1, time.time())
    else:
        login_attempts[ip] = (1, time.time())

def get_client_ip():
    """Récupère l'adresse IP du client"""
    return request.remote_addr

# --- Base de données ---
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "z_data.db")
USERS_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS mesures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lat REAL NOT NULL,
                lng REAL NOT NULL,
                download REAL NOT NULL,
                upload REAL NOT NULL,
                ping REAL NOT NULL,
                operator TEXT NOT NULL,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            )
        """)
    with sqlite3.connect(USERS_DB) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                plan TEXT DEFAULT 'free',
                trial_start TEXT,
                paid_until TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

def enregistrer_mesure(lat, lng, download, upload, ping, operator, ip_address):
    with sqlite3.connect(DB_PATH) as db:
        db.execute(
            "INSERT INTO mesures (lat, lng, download, upload, ping, operator, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (lat, lng, download, upload, ping, operator, ip_address, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )

def charger_mesures():
    with sqlite3.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM mesures").fetchall()
        return [dict(row) for row in rows]

def get_current_user():
    if 'user_id' in session:
        with sqlite3.connect(USERS_DB) as db:
            db.row_factory = sqlite3.Row
            user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            return dict(user) if user else None
    return None

def check_access(user):
    if not user:
        return False
    if user['plan'] == 'premium':
        if user['paid_until']:
            paid_until = datetime.strptime(user['paid_until'], '%Y-%m-%d')
            return datetime.now() < paid_until
        return False
    else:
        if user['trial_start']:
            trial_start = datetime.strptime(user['trial_start'], '%Y-%m-%d')
            return datetime.now() < trial_start + timedelta(days=7)
        return False

def mesurer_ping_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        start = time.time()
        s.sendto(b'ping', ('8.8.8.8', 80))
        s.close()
        return round((time.time() - start) * 1000, 2)
    except:
        return 999

# --- Fonction de conseil intelligent ---
def obtenir_conseil(ping, download, operator):
    if ping > 200 or download < 1:
        return "📵 Connexion trop lente. Veuillez redémarrer votre téléphone, ou déplacez-vous vers un espace ouvert."
    elif ping > 100 or download < 5:
        return "📶 Signal faible. Essayez de vous diriger vers une fenêtre ou un espace ouvert. Vérifiez si vous n'êtes pas dans un sous-sol."
    elif download > 10:
        return "✅ Excellente connexion ! C'est le bon endroit pour naviguer, regarder des vidéos ou télécharger."
    else:
        return "🔍 Connexion moyenne. Vous pouvez surfer sur le web, mais les vidéos risquent de prendre du temps. Essayez le Radar pour trouver mieux."

# --- Routes d'authentification ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    ip = get_client_ip()
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect(USERS_DB) as db:
            try:
                db.execute("INSERT INTO users (email, password, trial_start) VALUES (?, ?, ?)",
                           (email, generate_password_hash(password), datetime.now().strftime('%Y-%m-%d')))
                db.commit()
                flash("Compte créé ! Essai gratuit de 1 semaine.", "success")
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash("Cet email est déjà utilisé.", "error")
    return render_template('login.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = get_client_ip()
    if request.method == 'POST':
        if not check_rate_limit(ip):
            flash("Trop de tentatives. Veuillez attendre 5 minutes.", "error")
            return redirect(url_for('login'))
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect(USERS_DB) as db:
            db.row_factory = sqlite3.Row
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash("Connexion réussie!", "success")
            return redirect(url_for('index'))
        register_attempt(ip)
        flash("Email ou mot de passe incorrect.", "error")
    return render_template('login.html', mode='login')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# --- Routes principales ---
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/test', methods=['POST'])
@login_required
def tester_connexion():
    try:
        data = request.get_json()
        lat, lng, operator = data.get('lat'), data.get('lng'), data.get('operator', 'Inconnu')
        ip = get_client_ip()
        ping = mesurer_ping_local()
        if ping < 50:
            download = 50.0
            upload = 20.0
        elif ping < 150:
            download = 10.0
            upload = 5.0
        else:
            download = 1.0
            upload = 0.5
        enregistrer_mesure(lat, lng, download, upload, ping, operator, ip)
        conseil = obtenir_conseil(ping, download, operator)
        resultat = {'lat': lat, 'lng': lng, 'download': round(download, 2),
                    'upload': round(upload, 2), 'ping': round(ping, 2), 'operator': operator, 'conseil': conseil}
        socketio.emit('nouvelle_mesure', resultat)
        return jsonify(resultat), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/radar', methods=['POST'])
@login_required
def radar():
    try:
        data = request.get_json()
        lat, lng = data.get('lat'), data.get('lng')
        points = [
            {'dir': 'Nord',   'lat': lat + 0.001, 'lng': lng},
            {'dir': 'Sud',    'lat': lat - 0.001, 'lng': lng},
            {'dir': 'Est',    'lat': lat, 'lng': lng + 0.001},
            {'dir': 'Ouest',  'lat': lat, 'lng': lng - 0.001},
        ]
        resultats = []
        for point in points:
            ping = mesurer_ping_local()
            if ping < 50:
                download = 50.0
            elif ping < 150:
                download = 10.0
            else:
                download = 1.0
            resultats.append({
                'direction': point['dir'],
                'download': download,
                'ping': ping
            })
        meilleure = max(resultats, key=lambda x: x['download'])
        return jsonify({'resultats': resultats, 'meilleure': meilleure}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin')
@login_required
def admin():
    data = charger_mesures()
    return render_template_string('''
        <h1>TOUTES LES DONNÉES</h1>
        <table border="1">
            <tr>
                <th>ID</th><th>Latitude</th><th>Longitude</th><th>Download</th><th>Upload</th><th>Ping</th><th>Opérateur</th><th>IP</th><th>Date</th>
            </tr>
            {% for item in data %}
            <tr>
                <td>{{ item['id'] }}</td>
                <td>{{ item['lat'] }}</td>
                <td>{{ item['lng'] }}</td>
                <td>{{ item['download'] }}</td>
                <td>{{ item['upload'] }}</td>
                <td>{{ item['ping'] }}</td>
                <td>{{ item['operator'] }}</td>
                <td>{{ item['ip_address'] }}</td>
                <td>{{ item['timestamp'] }}</td>
            </tr>
            {% endfor %}
        </table>
        <a href="/">Retour</a>
    ''', data=data)

@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory('.', 'manifest.json')

@app.route('/service-worker.js')
def serve_sw():
    return send_from_directory('.', 'service-worker.js')

if __name__ == '__main__':
    init_db()
    from waitress import serve
    print("Z-Data Network démarré: http://127.0.0.1:5000")
    serve(app, host='0.0.0.0', port=5000, threads=8)