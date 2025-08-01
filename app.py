from flask import Flask, request, jsonify, render_template_string
from db_config import get_db_connection
from auth_utils import generate_token
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# HTML FORMS FOR MANUAL BROWSER TESTING
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
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
</head>
<body>
  <h2>Login</h2>
  <form id="loginForm">
    <label>Username: <input type="text" id="username" required></label><br><br>
    <label>Password: <input type="password" id="password" required></label><br><br>
    <button type="submit">Login</button>
  </form>

  <div id="result" style="margin-top: 20px; color: green;"></div>

  <script>
    const form = document.getElementById('loginForm');
    const result = document.getElementById('result');

    form.addEventListener('submit', function (e) {
      e.preventDefault();

      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;

      fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      })
      .then(response => response.json())
      .then(data => {
        if (data.token) {
          result.style.color = 'green';
          result.textContent = 'Login successful! Token: ' + data.token;
          localStorage.setItem('token', data.token);
          localStorage.setItem('role', data.role);
          // Redirect or inform frontend here
        } else {
          result.style.color = 'red';
          result.textContent = 'Login failed: ' + (data.message || 'Unknown error');
        }
      })
      .catch(err => {
        result.style.color = 'red';
        result.textContent = 'Error: ' + err.message;
      });
    });
  </script>
</body>
</html>
"""


# REGISTER ROUTE

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(register_form_html)

    # Accept both JSON and form data
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

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (
            username,
            generate_password_hash(password),
            role
        ))
        conn.commit()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({"message": "User registered successfully"}), 201


# LOGIN ROUTE

@app.route('/login', methods=['POST'])
def login():
    # Only allow JSON payloads
    if not request.is_json:
        return jsonify({"error": "Request must be in JSON format"}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            token = generate_token(user['id'], user['role'])
            return jsonify({"token": token, "role": user['role']}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# RUN APP

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

