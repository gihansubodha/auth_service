from flask import Flask, request, jsonify, render_template_string
from db_config import get_db_connection
from auth_utils import generate_token
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

register_form_html = """
<!doctype html>
<title>Register</title>
<h2>Register User</h2>
<form method="post" action="/register">
  Username: <input type="text" name="username" /><br/>
  Password: <input type="password" name="password" /><br/>
  Role: <input type="text" name="role" /><br/>
  <input type="submit" value="Register" />
</form>
"""

login_form_html = """
<!doctype html>
<title>Login</title>
<h2>Login</h2>
<form method="post" action="/login">
  Username: <input type="text" name="username" /><br/>
  Password: <input type="password" name="password" /><br/>
  <input type="submit" value="Login" />
</form>
"""

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(register_form_html)

    # POST: Support form data or JSON
    if request.is_json:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

    if not all([username, password, role]):
        return jsonify({"error": "Missing username, password or role"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (
        username,
        generate_password_hash(password),
        role
    ))
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({"message": "User registered successfully"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request must be JSON"}), 400

    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        cursor.nextset()  # Clear any remaining unread results

        if user and check_password_hash(user['password'], password):
            token = generate_token(user['id'], user['role'])
            return jsonify({"token": token, "role": user['role']})
        return jsonify({"message": "Invalid credentials"}), 401
    finally:
        cursor.close()
        conn.close()

    if user and check_password_hash(user['password'], password):
        token = generate_token(user['id'], user['role'])
        return jsonify({"token": token, "role": user['role']})
    return jsonify({"message": "Invalid credentials"}), 401

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
