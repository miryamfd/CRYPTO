from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from services.auth_service import register_user, login_user
from database.db import add_log



auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, result = login_user(username, password)
        if ok:
            session["user_id"]  = result["id"]
            session["username"] = result["username"]
            session["role"]     = result["role"]
            session["password"] = password
            add_log(result["id"], "login", ip=request.remote_addr)
            return redirect(url_for("dashboard"))
        else:
            flash(result, "error")
    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "error")
        else:
            ok, result = register_user(username, email, password)
            if ok:
                # NOTE coéquipière crypto : décommenter quand crypto_service.py est prêt
                # generate_keys(result, password)
                add_log(result, "register", f"Nouvel utilisateur : {username}", request.remote_addr)
                flash("Compte créé ! Vous pouvez vous connecter.", "success")
                return redirect(url_for("auth.login"))
            else:
                flash(result, "error")
    return render_template("register.html")


@auth_bp.route("/logout")
def logout():
    if "user_id" in session:
        add_log(session["user_id"], "logout", ip=request.remote_addr)
    session.clear()
    return redirect(url_for("auth.login"))