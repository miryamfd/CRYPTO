import os

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, "database", "crypto_cloud.db")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
KEYS_DIR    = os.path.join(BASE_DIR, "keys")

DEFAULT_QUOTA = 100 * 1024 * 1024   # 100 MB
RSA_KEY_SIZE  = 2048
SECRET_KEY    = "change_this_in_production_please"
DEBUG         = True

ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg",
    "gif", "docx", "xlsx", "zip", "mp4"
}
