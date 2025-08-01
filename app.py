from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
from db_config import get_db_connection

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = 'your-secret-key'
jwt = JWTManager(app)

#  Role checker
def check_role(required_roles):
    def wrapper(fn):
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
        decorator.__name__ = fn.__name__
        return decorator
    return wrapper

#  Register user (Admin only)
@app.route('/register', methods=['POST'])
@jwt_required()
@check_role(['admin'])
def register():
    data = request.json
    username = data['username']
    password = data['password']  
    role = data['role']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                   (username, password, role))
    conn.commit()
    conn.close()
    return jsonify({"msg": "User registered successfully"})

# Login user (Plain text)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        token = create_access_token(identity=username)
        return jsonify({"token": token, "role": user['role']})
    return jsonify({"msg": "Invalid credentials"}), 401

#  Delete user (Admin only)
@app.route('/delete_user', methods=['DELETE'])
@jwt_required()
@check_role(['admin'])
def delete_user():
    data = request.json
    username = data['username']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE username=%s", (username,))
    conn.commit()
    conn.close()
    return jsonify({"msg": "User deleted"})

#  Health check
@app.route('/', methods=['GET'])
def health():
    return jsonify({"status": "Auth Service Running"})

#  Protected route test (Seller)
@app.route('/protected_seller', methods=['GET'])
@jwt_required()
@check_role(['seller'])
def seller_only():
    return jsonify({"msg": "Hello Seller! Protected route works."}) 
    
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

