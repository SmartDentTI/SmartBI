import os, hashlib, traceback
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect
import psycopg2

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get("SECRET_KEY", "smartbi-dev-key")
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 900

@app.before_request
def make_session_non_permanent():
    session.permanent = False

DB_CONFIG = {
    "host":     os.environ.get("DB_HOST",     "localhost"),
    "database": os.environ.get("DB_NAME",     "railway"),
    "user":     os.environ.get("DB_USER",     "postgres"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "port":     os.environ.get("DB_PORT",     "5432"),
}

def get_conn():
    return psycopg2.connect(**DB_CONFIG)

def hash_pwd(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

APP_ID = 'smartbi'

def get_user(username):
    try:
        conn = get_conn(); cur = conn.cursor()
        cur.execute(
            "SELECT username, nombre, rol, pwd, activo, sucursal FROM usuarios WHERE username = %s",
            (username,)
        )
        row = cur.fetchone(); conn.close()
        if not row: return None
        return {"username": row[0], "nombre": row[1], "rol": row[2],
                "pwd": row[3], "activo": row[4], "sucursal": row[5]}
    except:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            if request.is_json:
                return jsonify({"ok": False, "msg": "No autenticado"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if "user" in session:
            return redirect("/")
        return render_template("login.html")

    data     = request.json or {}
    username = data.get("username", "").strip()
    pwd      = data.get("password", "")
    user     = get_user(username)

    if not user or not user["activo"]:
        return jsonify({"ok": False, "msg": "Usuario no encontrado o inactivo"}), 401
    if user["pwd"] != hash_pwd(pwd):
        return jsonify({"ok": False, "msg": "Contraseña incorrecta"}), 401

    try:
        conn = get_conn(); cur = conn.cursor()
        cur.execute(
            "SELECT 1 FROM app_accesos WHERE username = %s AND app = %s",
            (username, APP_ID)
        )
        tiene_acceso = cur.fetchone()
        conn.close()
    except:
        tiene_acceso = None

    if not tiene_acceso:
        return jsonify({"ok": False, "msg": "No tienes acceso a esta aplicación"}), 403

    session["user"]     = user["username"]
    session["nombre"]   = user["nombre"]
    session["rol"]      = user["rol"]
    session["sucursal"] = user["sucursal"] or ""
    return jsonify({"ok": True})

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@login_required
def home():
    return render_template("index.html",
        usuario=session.get("nombre"),
        username=session.get("user"),
        rol=session.get("rol"),
        sucursal=session.get("sucursal", "")
    )

if __name__ == "__main__":
    app.run(debug=False, port=5000, use_reloader=False, host="127.0.0.1")
