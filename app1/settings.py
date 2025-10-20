import os
import json
from pathlib import Path
from django.core.management.utils import get_random_secret_key

BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------
# Local secrets helper with SQLite fallback
# ------------------------------
LOCAL_SECRETS_PATH = os.path.join(BASE_DIR, "local_secrets.json")

def get_local_secrets():
    """Retrieve local secrets from a JSON file, fallback to defaults if missing."""
    if not os.path.exists(LOCAL_SECRETS_PATH):
        print("⚠️ local_secrets.json not found — using default SQLite setup.")
        return {
            "SECRET_KEY": get_random_secret_key(),
            "DB_NAME": os.path.join(BASE_DIR, "db.sqlite3"),
            "USE_SQLITE": True
        }
    with open(LOCAL_SECRETS_PATH, "r") as file:
        secrets = json.load(file)
        secrets["USE_SQLITE"] = False
        return secrets

secrets = get_local_secrets()

# ------------------------------
# Django core settings
# ------------------------------
SECRET_KEY = secrets["SECRET_KEY"]
DEBUG = True  # Set to False in production
ALLOWED_HOSTS = ["*"]

# Installed apps
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app1',
    'tailwind',
    'theme',
    'django_browser_reload',
    'corsheaders',
]

# Middleware stack
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_browser_reload.middleware.BrowserReloadMiddleware',
]

ROOT_URLCONF = 'app1.urls'

# Template configuration
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'app1/templates'),
            os.path.join(BASE_DIR, 'theme/templates')
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'app1.wsgi.application'

# ------------------------------
# Database configuration
# ------------------------------
if secrets.get("USE_SQLITE"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": secrets["DB_NAME"],
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": secrets.get("DB_NAME"),
            "USER": secrets.get("DB_USER"),
            "PASSWORD": secrets.get("DB_PASSWORD"),
            "HOST": secrets.get("DB_HOST", "localhost"),
            "PORT": secrets.get("DB_PORT", 5432),
        }
    }

# ------------------------------
# Memcached cache helper (optional)
# ------------------------------
MEMCACHED_HOST = os.environ.get('MEMCACHED_HOST', '127.0.0.1')
MEMCACHED_PORT = int(os.environ.get('MEMCACHED_PORT', 11211))
DEFAULT_MEMCACHED_ENDPOINT = f"{MEMCACHED_HOST}:{MEMCACHED_PORT}"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.memcached.PyMemcacheCache",
        "LOCATION": DEFAULT_MEMCACHED_ENDPOINT,
    }
}

# ------------------------------
# Local file storage
# ------------------------------
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

STATIC_URL = '/static/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]

# ------------------------------
# Sessions & security settings
# ------------------------------
SESSION_COOKIE_AGE = 7 * 24 * 60 * 60  # 7 days
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False") == "True"
CSRF_COOKIE_SECURE = os.environ.get("CSRF_COOKIE_SECURE", "False") == "True"

# ------------------------------
# External services (local placeholder)
# ------------------------------
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
