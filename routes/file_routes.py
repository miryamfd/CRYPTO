"""
file_routes.py
---------------
Routes Flask pour la gestion des fichiers.
POST /upload
GET  /download/<file_id>
POST /delete/<file_id>
POST /share
"""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import (
    Blueprint, request, session, redirect,
    url_for, flash, send_file, after_this_request
)
import io

from services.file_service import (
    upload_file, download_file,
    delete_file, share_file,
    list_user_files, list_shared_with_me
)

file_bp = Blueprint("files", __name__)


# ── Utilitaire : vérifier la session ─────────────────────────────────────────

def _get_current_user():
    """Retourne (user_id, password) depuis la session ou (None, None)."""
    user_id  = session.get("user_id")
    password = session.get("password")   # stocké en session par auth_routes
    return user_id, password


# ── Upload ────────────────────────────────────────────────────────────────────

@file_bp.route("/upload", methods=["POST"])
def upload():
    user_id, password = _get_current_user()
    if not user_id:
        return redirect(url_for("auth.login"))

    # Récupère le fichier envoyé par le formulaire HTML
    file_obj = request.files.get("file")
    if not file_obj or file_obj.filename == "":
        flash("Aucun fichier sélectionné.", "error")
        return redirect(url_for("dashboard"))

    ok, message = upload_file(
        user_id  = user_id,
        file_obj = file_obj,
        password = password,
        ip       = request.remote_addr
    )

    if ok:
        flash(f"✅ '{file_obj.filename}' chiffré et uploadé avec succès.", "success")
    else:
        flash(f"❌ Erreur : {message}", "error")

    return redirect(url_for("dashboard"))


# ── Download ──────────────────────────────────────────────────────────────────

@file_bp.route("/download/<int:file_id>")
def download(file_id):
    user_id, password = _get_current_user()
    if not user_id:
        return redirect(url_for("auth.login"))

    ok, result, original_name = download_file(
        user_id  = user_id,
        file_id  = file_id,
        password = password,
        ip       = request.remote_addr
    )

    if not ok:
        flash(f"❌ {result}", "error")
        return redirect(url_for("dashboard"))

    # Envoie le fichier déchiffré au navigateur comme téléchargement
    return send_file(
        io.BytesIO(result),
        download_name = original_name,
        as_attachment = True
    )


# ── Suppression ───────────────────────────────────────────────────────────────

@file_bp.route("/delete/<int:file_id>", methods=["POST"])
def delete(file_id):
    user_id, password = _get_current_user()
    if not user_id:
        return redirect(url_for("auth.login"))

    ok, message = delete_file(
        user_id = user_id,
        file_id = file_id,
        ip      = request.remote_addr
    )

    if ok:
        flash("🗑️ Fichier supprimé.", "success")
    else:
        flash(f"❌ {message}", "error")

    return redirect(url_for("dashboard"))


# ── Partage ───────────────────────────────────────────────────────────────────

@file_bp.route("/share", methods=["POST"])
def share():
    user_id, password = _get_current_user()
    if not user_id:
        return redirect(url_for("auth.login"))

    file_id            = request.form.get("file_id",    type=int)
    recipient_username = request.form.get("share_with", "").strip()

    if not file_id or not recipient_username:
        flash("Données manquantes pour le partage.", "error")
        return redirect(url_for("dashboard"))

    ok, message = share_file(
        owner_id           = user_id,
        file_id            = file_id,
        recipient_username = recipient_username,
        owner_password     = password,
        ip                 = request.remote_addr
    )

    if ok:
        flash(f" Fichier partagé avec '{recipient_username}'.", "success")
    else:
        flash(f" {message}", "error")

    return redirect(url_for("dashboard"))