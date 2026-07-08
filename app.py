import os, hmac, hashlib, base64, json, time
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect

app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get("SECRET_KEY", "smartbi-dev-key")
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 900

@app.before_request
def make_session_non_permanent():
    session.permanent = False

APP_ID     = "smartbi"
SSO_SECRET = os.environ.get("SSO_SECRET", "smartapps-sso-dev-2026")
PORTAL_URL = os.environ.get("PORTAL_URL", "https://smartapps-production.up.railway.app")

def verify_sso_token(token, max_age=90):
    try:
        payload_b64, sig = token.rsplit(".", 1)
        expected = hmac.new(SSO_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        if payload.get("a") != APP_ID:
            return None
        if int(time.time()) - payload.get("t", 0) > max_age:
            return None
        return payload
    except Exception:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            if request.is_json:
                return jsonify({"ok": False, "msg": "No autenticado"}), 401
            return redirect(PORTAL_URL)
        return f(*args, **kwargs)
    return decorated

@app.route("/auth")
def sso_auth():
    token   = request.args.get("token", "")
    payload = verify_sso_token(token)
    if not payload:
        return redirect(PORTAL_URL)
    session.update({"user": payload["u"], "nombre": payload["n"],
                    "rol": payload["r"], "sucursal": payload["s"]})
    return redirect("/")

@app.route("/login")
def login():
    return redirect(PORTAL_URL)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(PORTAL_URL)

REPORTES = [
    {
        "id":     "dashboard",
        "nombre": "Dashboard",
        "url":    "https://app.powerbi.com/view?r=eyJrIjoiY2UzZmFhZGYtZDYwZS00MjE2LWFmNzAtNDZhNjQ2ODQ1MDVkIiwidCI6IjdlNmNmZjIwLWM1OTEtNGRkMy05NDJhLWJiNTc5OWY4OTFmMSJ9&pageName=0db1d61e7afaccd70b04",
    },
]

@app.route("/")
@login_required
def home():
    return render_template("index.html",
        usuario=session.get("nombre"),
        username=session.get("user"),
        rol=session.get("rol"),
        sucursal=session.get("sucursal", ""),
        reportes=REPORTES,
    )

if __name__ == "__main__":
    app.run(debug=False, port=5000, use_reloader=False, host="127.0.0.1")
