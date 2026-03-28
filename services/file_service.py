"""
file_service.py  v2
--------------------
Logique métier : upload, download, suppression, partage de fichiers.

Améliorations v2 :
    - Validation magic bytes + taille via file_validator.py
    - Historique de téléchargements (table download_history)
"""

import os
import sys
import uuid

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from config import STORAGE_DIR, KEYS_DIR
from database.db import (
    add_file, get_file_by_id, get_files_by_user,
    delete_file as db_delete_file,
    add_log,
    share_file as db_share_file,
    get_files_shared_with_user,
    get_user_by_username,
    fetch_all, execute
)
from services.quota_service  import check_quota, add_to_quota, free_from_quota
from services.file_validator import validate_file

from services.crypto_service import (
    encrypt_file, decrypt_file, reencrypt_aes_key,
    sign_file, verify_signature, hash_file_sha256,
)


# ── Chemins ───────────────────────────────────────────────────────────────────

def _get_user_storage_dir(user_id):
    path = os.path.join(STORAGE_DIR, f"user_{user_id}")
    os.makedirs(path, exist_ok=True)
    return path

def _get_user_keys_dir(user_id):
    return os.path.join(KEYS_DIR, f"user_{user_id}")

def _get_public_key_pem(user_id):
    path = os.path.join(_get_user_keys_dir(user_id), "public.pem")
    if not os.path.exists(path): return None
    with open(path, "r") as f: return f.read()

def _get_private_key_pem(user_id):
    path = os.path.join(_get_user_keys_dir(user_id), "private.pem")
    if not os.path.exists(path): return None
    with open(path, "r") as f: return f.read()


# ── Historique téléchargements ────────────────────────────────────────────────

def _init_download_history_table():
    """Crée la table download_history si elle n'existe pas."""
    execute("""
        CREATE TABLE IF NOT EXISTS download_history (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id       INTEGER NOT NULL,
            user_id       INTEGER NOT NULL,
            downloaded_at TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

def _add_download_history(file_id, user_id):
    """Enregistre un téléchargement."""
    _init_download_history_table()
    execute(
        "INSERT INTO download_history (file_id, user_id) VALUES (?, ?)",
        (file_id, user_id)
    )

def get_download_history(file_id):
    """
    Retourne l'historique des téléchargements d'un fichier.
    [ { username, downloaded_at }, ... ]
    """
    _init_download_history_table()
    return fetch_all("""
        SELECT u.username, dh.downloaded_at
        FROM download_history dh
        JOIN users u ON dh.user_id = u.id
        WHERE dh.file_id = ?
        ORDER BY dh.downloaded_at DESC
    """, (file_id,))

def get_download_count(file_id):
    """Retourne le nombre total de téléchargements d'un fichier."""
    _init_download_history_table()
    rows = fetch_all(
        "SELECT COUNT(*) as cnt FROM download_history WHERE file_id = ?",
        (file_id,)
    )
    return rows[0]["cnt"] if rows else 0


# ── Upload ────────────────────────────────────────────────────────────────────

def upload_file(user_id, file_obj, password, ip=None):
    """
    Chiffre et stocke un fichier.

    Ordre des vérifications :
        1. Validation (extension + magic bytes + taille max)
        2. Quota suffisant
        3. Chiffrement AES + RSA
        4. Signature + SHA256
        5. Sauvegarde disque + DB
    """

    original_name = file_obj.filename
    file_bytes    = file_obj.read()

    # 1. Validation complète
    ok, message = validate_file(original_name, file_bytes)
    if not ok:
        return False, message

    file_size = len(file_bytes)

    # 2. Quota
    ok, message = check_quota(user_id, file_size)
    if not ok:
        return False, message

    # 3. Clés
    public_key_pem  = _get_public_key_pem(user_id)
    private_key_pem = _get_private_key_pem(user_id)
    if not public_key_pem:
        return False, "Clé publique introuvable. Contactez l'administrateur."
    if not private_key_pem:
        return False, "Clé privée introuvable. Contactez l'administrateur."

    # 4. Chiffrement + signature + hash
    encrypted_bytes, encrypted_aes_key = encrypt_file(file_bytes, public_key_pem)
    signature = sign_file(file_bytes, private_key_pem, password)
    sha256    = hash_file_sha256(file_bytes)

    # 5. Sauvegarde disque
    stored_name = uuid.uuid4().hex + ".enc"
    key_name    = stored_name.replace(".enc", ".key")
    storage_dir = _get_user_storage_dir(user_id)

    with open(os.path.join(storage_dir, stored_name), "wb") as f:
        f.write(encrypted_bytes)
    with open(os.path.join(storage_dir, key_name), "wb") as f:
        f.write(encrypted_aes_key)

    # 6. DB + quota + log
    add_file(user_id, original_name, stored_name, file_size, sha256, signature)
    add_to_quota(user_id, file_size)
    add_log(user_id, "upload",
            f"Uploadé : {original_name} ({file_size} octets)", ip)

    return True, "ok"


# ── Download ──────────────────────────────────────────────────────────────────

def download_file(user_id, file_id, password, ip=None):
    """
    Déchiffre et retourne le contenu d'un fichier.
    Vérifie l'intégrité SHA256 et la signature RSA.
    Enregistre dans l'historique.

    Retourne (True, bytes, nom) ou (False, message, "")
    """

    file = get_file_by_id(file_id)
    if not file:
        return False, "Fichier introuvable.", ""

    owner_id = file["owner_id"]

    # Vérification accès : propriétaire ou destinataire d'un partage
    if owner_id != user_id:
        shared_ids = [s["id"] for s in get_files_shared_with_user(user_id)]
        if file_id not in shared_ids:
            return False, "Accès refusé.", ""

    # Lecture fichiers chiffrés
    storage_dir = _get_user_storage_dir(owner_id)
    enc_path    = os.path.join(storage_dir, file["stored_name"])
    key_path    = enc_path.replace(".enc", ".key")

    if not os.path.exists(enc_path) or not os.path.exists(key_path):
        return False, "Fichier introuvable sur le disque.", ""

    with open(enc_path, "rb") as f: encrypted_bytes   = f.read()
    with open(key_path, "rb") as f: encrypted_aes_key = f.read()

    # Déchiffrement
    private_key_pem = _get_private_key_pem(owner_id)
    if not private_key_pem:
        return False, "Clé privée introuvable.", ""

    file_bytes = decrypt_file(
        encrypted_bytes, encrypted_aes_key, private_key_pem, password
    )

    # Vérification intégrité SHA256
    if hash_file_sha256(file_bytes) != file["sha256_hash"]:
        return False, "Intégrité compromise : le fichier a été altéré !", ""

    # Vérification signature RSA
    public_key_pem = _get_public_key_pem(owner_id)
    if not verify_signature(file_bytes, file["signature"], public_key_pem):
        return False, "Signature invalide : authenticité non vérifiée !", ""

    # Historique + log
    _add_download_history(file_id, user_id)
    add_log(user_id, "download",
            f"Téléchargé : {file['original_name']}", ip)

    return True, file_bytes, file["original_name"]


# ── Suppression ───────────────────────────────────────────────────────────────

def delete_file(user_id, file_id, ip=None):
    """Supprime un fichier du disque + DB + libère le quota."""

    file = get_file_by_id(file_id)
    if not file:
        return False, "Fichier introuvable."
    if file["owner_id"] != user_id:
        return False, "Vous ne pouvez supprimer que vos propres fichiers."

    storage_dir = _get_user_storage_dir(user_id)
    enc_path    = os.path.join(storage_dir, file["stored_name"])
    key_path    = enc_path.replace(".enc", ".key")

    for path in [enc_path, key_path]:
        if os.path.exists(path):
            os.remove(path)

    db_delete_file(file_id)
    free_from_quota(user_id, file["file_size"])
    add_log(user_id, "delete",
            f"Supprimé : {file['original_name']}", ip)

    return True, "ok"


# ── Partage ───────────────────────────────────────────────────────────────────

def share_file(owner_id, file_id, recipient_username, owner_password, ip=None):
    """
    Partage un fichier en rechiffrant la clé AES
    avec la clé publique du destinataire.
    """

    file = get_file_by_id(file_id)
    if not file:
        return False, "Fichier introuvable."
    if file["owner_id"] != owner_id:
        return False, "Vous ne pouvez partager que vos propres fichiers."

    recipient = get_user_by_username(recipient_username)
    if not recipient:
        return False, f"Utilisateur '{recipient_username}' introuvable."
    if recipient["id"] == owner_id:
        return False, "Vous ne pouvez pas partager un fichier avec vous-même."

    recipient_id      = recipient["id"]
    owner_priv_pem    = _get_private_key_pem(owner_id)
    recipient_pub_pem = _get_public_key_pem(recipient_id)

    if not owner_priv_pem:
        return False, "Clé privée du propriétaire introuvable."
    if not recipient_pub_pem:
        return False, f"Clé publique de '{recipient_username}' introuvable."

    # Clé AES originale
    storage_dir = _get_user_storage_dir(owner_id)
    key_path    = os.path.join(
        storage_dir,
        file["stored_name"].replace(".enc", ".key")
    )
    if not os.path.exists(key_path):
        return False, "Clé AES introuvable sur le disque."

    with open(key_path, "rb") as f:
        encrypted_aes_key_owner = f.read()

    # Rechiffrement pour le destinataire
    encrypted_aes_key_recipient = reencrypt_aes_key(
        encrypted_aes_key_owner,
        owner_priv_pem,
        owner_password,
        recipient_pub_pem
    )

    # Sauvegarde dans le dossier du destinataire
    recipient_dir = _get_user_storage_dir(recipient_id)
    with open(os.path.join(
        recipient_dir,
        file["stored_name"].replace(".enc", f"_shared_by_{owner_id}.key")
    ), "wb") as f:
        f.write(encrypted_aes_key_recipient)

    result = db_share_file(file_id, owner_id, recipient_id)
    if result is None:
        return False, f"Ce fichier est déjà partagé avec '{recipient_username}'."

    add_log(owner_id, "share",
            f"'{file['original_name']}' → {recipient_username}", ip)

    return True, "ok"


# ── Listes ────────────────────────────────────────────────────────────────────

def list_user_files(user_id):
    """Retourne les fichiers de l'utilisateur + compteur de téléchargements."""
    files = get_files_by_user(user_id)
    result = []
    for f in files:
        d = dict(f)
        d["download_count"] = get_download_count(f["id"])
        result.append(d)
    return result

def list_shared_with_me(user_id):
    """Retourne les fichiers partagés avec l'utilisateur."""
    return get_files_shared_with_user(user_id)