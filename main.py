from flask import Flask, render_template, session, redirect, url_for

from config import SECRET_KEY, DEBUG
from database.db import (
    init_db, get_user_by_username, create_user,
    get_logs_by_user, execute
)
from routes.auth_routes  import auth_bp
from routes.file_routes  import file_bp
from routes.admin_routes import admin_bp
from services.auth_service  import hash_password
from services.quota_service import get_quota_stats
from services.file_service  import list_user_files, list_shared_with_me

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ── Initialisation DB ─────────────────────────────────────────────────────────
with app.app_context():
    init_db()

with app.app_context():
    if not get_user_by_username("admin"):
        user_id = create_user("admin", "admin@cloud.com", hash_password("admin123"), role="admin")
        print("[ADMIN] Compte admin créé — identifiants : admin / admin123")

# ── Blueprints ────────────────────────────────────────────────────────────────
app.register_blueprint(auth_bp)
app.register_blueprint(file_bp)
app.register_blueprint(admin_bp)

# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    stats   = get_quota_stats(user_id)

    return render_template(
        "dashboard.html",
        files          = list_user_files(user_id),
        shared_files   = list_shared_with_me(user_id),
        logs           = get_logs_by_user(user_id),
        quota_used_mb  = stats["quota_used_mb"],
        quota_max_mb   = stats["quota_max_mb"],
        quota_percent  = stats["quota_percent"],
    )

# ── Admin (redirige vers le blueprint) ───────────────────────────────────────
@app.route("/admin")
def admin():
    return redirect(url_for("admin.admin_dashboard"))

if __name__ == "__main__":
    app.run(debug=DEBUG)