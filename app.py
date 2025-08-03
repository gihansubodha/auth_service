from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
from db_config import get_db_connection
from functools import wraps

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
jwt = JWTManager(app)

# ✅ Role checker decorator
def check_role(required_roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            current_user = get_jwt_identity()
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT role FROM users WHERE username=%s", (current_user,))
            user = cursor.fetchone()
            conn.close()
            if user and user['role'] in required_roles:
                return fn(*args, **kwargs)
            return jsonify({"msg": "Unauthorized"}), 403
        return decorator
    return wrapper

# ✅ Register user (Admin only)
@app.route('/register', methods=['POST'])
@jwt_required()
@check_role(['admin'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    if not all([username, password, role]):
        return jsonify({"msg": "All fields required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                   (username, password, role))
    conn.commit()
    conn.close()
    return jsonify({"msg": "User registered successfully"})

# ✅ Login user
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and user['password'] == password:
        token = create_access_token(identity=username)
        return jsonify({"token": token, "role": user['role']})

    return jsonify({"msg": "Invalid credentials"}), 401

# ✅ Get user info by username
@app.route('/get_user/<username>', methods=['GET'])
def get_user(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT id, username, role FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify(user)
    return jsonify({"msg": "User not found"}), 404

# ✅ Delete user (Admin only)
@app.route('/delete_user', methods=['DELETE'])
@jwt_required()
@check_role(['admin'])
def delete_user():
    data = request.json
    username = data.get('username')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username=%s", (username,))
    conn.commit()
    conn.close()
    return jsonify({"msg": "User deleted"})

# ✅ Get all users (Admin only)
@app.route("/all_users", methods=["GET"])
@jwt_required()
@check_role(['admin'])
def get_all_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT username, role FROM users")
        users = cursor.fetchall()
        conn.close()
        return jsonify({"users": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ Health check
@app.route('/', methods=['GET'])
def health():
    return jsonify({"status": "Auth Service Running"})

# ✅ Protected example
@app.route('/protected_seller', methods=['GET'])
@jwt_required()
@check_role(['seller'])
def seller_only():
    return jsonify({"msg": "Hello Seller! Protected route works."})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
