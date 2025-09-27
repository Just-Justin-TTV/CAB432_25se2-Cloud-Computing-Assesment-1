import os
import json
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------
# Django core settings
# ------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret")
DEBUG = os.environ.get("DEBUG", "True") == "True"
ALLOWED_HOSTS = ["*"]

# ------------------------------
# Memcached / Cache (AWS ElastiCache only)
# ------------------------------
MEMCACHED_HOST = os.environ["CACHE_HOST"]
MEMCACHED_PORT = int(os.environ.get("CACHE_PORT", 11211))

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.PyMemcacheCache',
        'LOCATION': f'{MEMCACHED_HOST}:{MEMCACHED_PORT}',
    }
}

# ------------------------------
# Ollama
# ------------------------------
OLLAMA_HOST = os.environ.get('OLLAMA_URL', 'http://localhost:11434')

# ------------------------------
# Installed apps
# ------------------------------
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

# ------------------------------
# Middleware
# ------------------------------
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

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'app1/templates'),
            os.path.join(BASE_DIR, 'theme/templates'),
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
# Database (temporary SQLite)
# ------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# ------------------------------
# Password validation
# ------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ------------------------------
# Internationalization
# ------------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ------------------------------
# Tailwind
# ------------------------------
TAILWIND_APP_NAME = 'theme'
INTERNAL_IPS = ["127.0.0.1"]

# ------------------------------
# CORS
# ------------------------------
CORS_ALLOW_ALL_ORIGINS = True  # development only

# ------------------------------
# AWS S3
# ------------------------------
USE_S3 = os.environ.get("USE_S3", "False") == "True"
AWS_PROFILE = os.environ.get("AWS_PROFILE", "CAB432-STUDENT")
AWS_REGION = os.environ.get("AWS_REGION", "ap-southeast-2")
AWS_STORAGE_BUCKET_NAME = os.environ.get("AWS_STORAGE_BUCKET_NAME", "justinsinghatwalbucket")
AWS_S3_ENDPOINT_URL = os.environ.get("AWS_S3_ENDPOINT_URL")

if USE_S3:
    def get_s3_client():
        session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
        return session.client("s3", endpoint_url=AWS_S3_ENDPOINT_URL)

# ------------------------------
# Cognito
# ------------------------------
COGNITO_REGION = os.environ.get("COGNITO_REGION", "ap-southeast-2")
COGNITO_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "ap-southeast-2_XEtlj9zEG")
COGNITO_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
COGNITO_CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET", "")
COGNITO_ADMIN_GROUP = os.environ.get("COGNITO_ADMIN_GROUP", "admin")

print(f"[DEBUG] Cognito config loaded: "
      f"region={COGNITO_REGION}, pool={COGNITO_USER_POOL_ID}, client_id={COGNITO_CLIENT_ID}")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://cab432-ollama:11434")