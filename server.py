from flask import Flask, request, jsonify
import os
import sqlite3
import hashlib
import datetime
import jwt
from collections import defaultdict
import time

app = Flask(__name__)

UPLOAD_FOLDER = "./uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DB_FILE = "users.db"
SECRET_KEY = "your_secret_key_here"  # IMPORTANT, CHANGE FOR YOUR OWN SECURITY WHEN YOU SELF HOST A SERVER!

rate_limit_store = defaultdict(list)

LOGIN_RATE_LIMIT = 5
UPLOAD_RATE_LIMIT = 5
REGISTER_RATE_LIMIT = 3600

def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expiration_date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """)
        conn.commit()
        conn.close()
    else:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tokens';")
        table_exists = cursor.fetchone()
        if not table_exists:
            cursor.execute("""
            CREATE TABLE tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expiration_date TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """)
            conn.commit()
        conn.close()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload["user_id"]
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user[0] if user else None
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def check_rate_limit(action, limit_time):
    current_time = time.time()
    action_times = rate_limit_store[action]
    rate_limit_store[action] = [t for t in action_times if current_time - t < limit_time]
    if len(rate_limit_store[action]) > 0:
        return False
    rate_limit_store[action].append(current_time)
    return True


@app.route("/register", methods=["POST"])
def register():
    if not check_rate_limit("register", REGISTER_RATE_LIMIT):
        return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
    
    data = request.json
    email = data.get("email")
    password = data.get("password")

    hashed_password = hash_password(password)

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({"message": "Registration successful"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 400


@app.route("/login", methods=["POST"])
def login():
    if not check_rate_limit("login", LOGIN_RATE_LIMIT):
        return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
    
    data = request.json
    email = data.get("email")
    password = data.get("password")
    hashed_password = hash_password(password)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ? AND password = ?", (email, hashed_password))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    user_id = user[0]
    expiration_date = datetime.datetime.utcnow() + datetime.timedelta(days=30)
    token = jwt.encode({"user_id": user_id, "exp": expiration_date}, SECRET_KEY, algorithm="HS256")

    cursor.execute("INSERT INTO tokens (user_id, token, expiration_date) VALUES (?, ?, ?)", 
                   (user_id, token, expiration_date.isoformat()))
    conn.commit()
    conn.close()

    return jsonify({"token": token}), 200


@app.route("/progress/upload", methods=["POST"])
def upload_progress():
    if not check_rate_limit("upload", UPLOAD_RATE_LIMIT):
        return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token.split(" ")[1]
    email = verify_token(token)
    if not email:
        return jsonify({"error": "Invalid or expired token"}), 401

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty file"}), 400

    user_folder = os.path.join(UPLOAD_FOLDER, email)
    os.makedirs(user_folder, exist_ok=True)
    save_path = os.path.join(user_folder, "ani-hsts")
    file.save(save_path)

    return jsonify({"message": "Progress file uploaded successfully"}), 200


@app.route("/progress", methods=["GET"])
def fetch_progress():
    token = request.headers.get("Authorization")
    if token and token.startswith("Bearer "):
        token = token.split(" ")[1]
    email = verify_token(token)
    if not email:
        return jsonify({"error": "Invalid or expired token"}), 401

    user_folder = os.path.join(UPLOAD_FOLDER, email)
    file_path = os.path.join(user_folder, "ani-hsts")

    progress = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split("\t")
                if len(parts) < 3:
                    continue
                progress.append({"progress": parts[0], "anime_id": parts[1], "title": parts[2]})
    except FileNotFoundError:
        return jsonify({"progress": []}), 200

    return jsonify({"progress": progress}), 200


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
