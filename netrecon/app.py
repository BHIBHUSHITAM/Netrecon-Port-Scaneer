"""
NetRecon - Main Flask Application
Network & Web Intelligence Dashboard
"""

import os
import json
from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, flash
)
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
import threading
from utils.port_scanner import scan_ports
from utils.url_scanner import scan_url

# Load env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///netrecon.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Allow OAuth over HTTP in dev
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

CORS(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ─── Models ─────────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(200), unique=True)
    name = db.Column(db.String(200))
    avatar = db.Column(db.String(500))
    scans = db.relationship('ScanHistory', backref='user', lazy=True)


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(20))  # 'port' or 'url'
    target = db.Column(db.String(500))
    result_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ─── Google OAuth ────────────────────────────────────────────────────────────

google_bp = make_google_blueprint(
    client_id=os.environ.get("GOOGLE_CLIENT_ID", ""),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET", ""),
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email",
           "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_to="google_login_callback"
)
app.register_blueprint(google_bp, url_prefix="/login")


@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", "danger")
        return False

    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info.", "danger")
        return False

    info = resp.json()
    google_id = info["id"]

    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User(
            google_id=google_id,
            email=info.get("email"),
            name=info.get("name"),
            avatar=info.get("picture")
        )
        db.session.add(user)
        db.session.commit()
    else:
        user.name = info.get("name")
        user.avatar = info.get("picture")
        db.session.commit()

    login_user(user)
    return False


@app.route("/google/callback")
def google_login_callback():
    return redirect(url_for("dashboard"))


# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    recent_scans = ScanHistory.query.filter_by(user_id=current_user.id)\
        .order_by(ScanHistory.created_at.desc()).limit(10).all()
    
    history = []
    for scan in recent_scans:
        try:
            result = json.loads(scan.result_json) if scan.result_json else {}
        except Exception:
            result = {}
        history.append({
            "id": scan.id,
            "type": scan.scan_type,
            "target": scan.target,
            "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M"),
            "result": result
        })

    return render_template("dashboard.html",
                           user=current_user,
                           history=history)


@app.route("/scanner/port")
@login_required
def port_scanner_page():
    return render_template("port_scanner.html", user=current_user)


@app.route("/scanner/url")
@login_required
def url_scanner_page():
    return render_template("url_scanner.html", user=current_user)


# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.route("/api/scan/port", methods=["POST"])
@login_required
def api_scan_port():
    data = request.get_json()
    target = data.get("target", "").strip()
    port_range = data.get("range", "common")
    custom_ports_str = data.get("custom_ports", "")

    if not target:
        return jsonify({"error": "Target IP/hostname is required"}), 400

    # Parse custom ports
    custom_ports = None
    if port_range == "custom" and custom_ports_str:
        try:
            custom_ports = []
            for part in custom_ports_str.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-")
                    custom_ports.extend(range(int(start), int(end) + 1))
                else:
                    custom_ports.append(int(part))
        except ValueError:
            return jsonify({"error": "Invalid custom port format"}), 400

    result = scan_ports(target, port_range, custom_ports)

    # Save to history
    history = ScanHistory(
        user_id=current_user.id,
        scan_type="port",
        target=target,
        result_json=json.dumps(result)
    )
    db.session.add(history)
    db.session.commit()

    return jsonify(result)


@app.route("/api/scan/url", methods=["POST"])
@login_required
def api_scan_url():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = scan_url(url)

    # Save to history
    history = ScanHistory(
        user_id=current_user.id,
        scan_type="url",
        target=url,
        result_json=json.dumps(result)
    )
    db.session.add(history)
    db.session.commit()

    return jsonify(result)


@app.route("/api/history")
@login_required
def api_history():
    scans = ScanHistory.query.filter_by(user_id=current_user.id)\
        .order_by(ScanHistory.created_at.desc()).limit(20).all()
    return jsonify([{
        "id": s.id,
        "type": s.scan_type,
        "target": s.target,
        "created_at": s.created_at.strftime("%Y-%m-%d %H:%M")
    } for s in scans])


@app.route("/api/user")
@login_required
def api_user():
    return jsonify({
        "name": current_user.name,
        "email": current_user.email,
        "avatar": current_user.avatar
    })


# ─── Demo mode (no OAuth needed for testing) ─────────────────────────────────

@app.route("/demo")
def demo_login():
    """Demo login for testing without Google OAuth."""
    user = User.query.filter_by(email="demo@netrecon.dev").first()
    if not user:
        user = User(
            google_id="demo_user_123",
            email="demo@netrecon.dev",
            name="Demo User",
            avatar="https://api.dicebear.com/7.x/avataaars/svg?seed=netrecon"
        )
        db.session.add(user)
        db.session.commit()
    login_user(user)
    return redirect(url_for("dashboard"))


# ─── Init ─────────────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host=host, port=port, debug=debug)
