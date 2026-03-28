import bcrypt
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from database.db import get_user_by_username, create_user


def hash_password(password: str) -> str:
    """Retourne le hash bcrypt du mot de passe."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed: str) -> bool:
    """Vérifie que le mot de passe correspond au hash stocké."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def register_user(username: str, email: str, password: str):
    """
    Inscrit un nouvel utilisateur.
    Retourne (True, user_id) si succès, (False, message_erreur) sinon.
    """
    if get_user_by_username(username):
        return False, "Ce nom d'utilisateur est déjà pris."
    if len(password) < 6:
        return False, "Le mot de passe doit faire au moins 6 caractères."
    password_hash = hash_password(password)
    user_id = create_user(username, email, password_hash)
    return True, user_id


def login_user(username: str, password: str):
    """
    Vérifie les identifiants.
    Retourne (True, user) si succès, (False, message_erreur) sinon.
    """
    user = get_user_by_username(username)
    if not user:
        return False, "Nom d'utilisateur ou mot de passe incorrect."
    if not user["is_active"]:
        return False, "Ce compte est suspendu."
    if not check_password(password, user["password_hash"]):
        return False, "Nom d'utilisateur ou mot de passe incorrect."
    return True, user
