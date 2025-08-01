from flask import Flask, request, jsonify
from db_config import get_connection
from auth_utils import generate_token, verify_token
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = generate_password_hash(data["password"])
    role = data["role"]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (username, password, role))
        conn.commit()
        return jsonify({"message": "User registered."})
    except:
        return jsonify({"error": "Username already exists."}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()

    if user and check_password_hash(user["password"], password):
        token = generate_token(user)
        return jsonify({"token": token, "role": user["role"]})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/verify", methods=["POST"])
def verify():
    token = request.headers.get("Authorization").split(" ")[1]
    decoded = verify_token(token)
    if decoded:
        return jsonify(decoded)
    return jsonify({"error": "Invalid token"}), 401

if __name__ == "__main__":
    app.run(debug=True)

import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Use Render's dynamic PORT
    app.run(host='0.0.0.0', port=port, debug=True)

