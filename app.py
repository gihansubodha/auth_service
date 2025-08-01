# cozy_auth/app.py
from flask import Flask, request, jsonify
import mysql.connector, jwt, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

SECRET = "cozy_secret"

def get_db():
    return mysql.connector.connect(
        host="YOUR_AIVEN_HOST", user="YOUR_USER", password="YOUR_PASS", database="cozy_auth"
    )

app = Flask(__name__)

def require_token(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization","").replace("Bearer ","")
            if not auth: return jsonify({"error":"Token missing"}),401
            try:
                data=jwt.decode(auth,SECRET,algorithms=["HS256"])
                if role and data['role']!=role and data['role']!='admin':
                    return jsonify({"error":"Forbidden"}),403
                request.user=data
            except Exception:
                return jsonify({"error":"Invalid token"}),401
            return f(*args,**kwargs)
        return wrapper
    return decorator

@app.route("/register", methods=["POST"])
@require_token(role="admin")
def register():
    u,p,r = request.json["username"], request.json["password"], request.json["role"]
    conn,cur = get_db(), get_db().cursor()
    try:
        cur.execute("INSERT INTO users(username,password,role) VALUES(%s,%s,%s)",(u,generate_password_hash(p),r))
        conn.commit()
        return jsonify({"msg":"User created"})
    except mysql.connector.Error:
        return jsonify({"error":"username exists"}),400
    finally:
        cur.close(); conn.close()

@app.route("/login", methods=["POST"])
def login():
    u,p = request.json["username"], request.json["password"]
    conn,cur = get_db(), get_db().cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE username=%s",(u,))
    user = cur.fetchone()
    cur.close(); conn.close()
    if user and check_password_hash(user['password'],p):
        token = jwt.encode({
            "username":user["username"], "role":user["role"],
            "exp":datetime.datetime.utcnow()+datetime.timedelta(hours=3)
        }, SECRET, algorithm="HS256")
        return jsonify({"token":token,"role":user["role"]})
    return jsonify({"error":"Invalid credentials"}),401

if __name__=="__main__":
    app.run(debug=True)
