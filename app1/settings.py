import os  
import json
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

BASE_DIR = Path(__file__).resolve().parent.parent

MEMCACHED_HOST = os.environ.get(
    'MEMCACHED_HOST',
    'n11605618-ollama-memcached.km2jzi.cfg.apse2.cache.amazonaws.com'
)
MEMCACHED_PORT = int(os.environ.get('MEMCACHED_PORT', 11211))

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.PyMemcacheCache',
        'LOCATION': f'{MEMCACHED_HOST}:{MEMCACHED_PORT}',
    }
}

OLLAMA_HOST = os.environ.get('OLLAMA_URL', 'http://localhost:11434')

# ------------------------------
# Django core settings
# ------------------------------

DEBUG = True  # Set to False in production
ALLOWED_HOSTS = ["*"]

# Installed apps including Tailwind, custom app, and dev tools
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
DB_USER = secrets["username"]
DB_PASSWORD = secrets["password"]
DB_NAME = secrets["dbname"]
DB_HOST = secrets["host"]
DB_PORT = secrets.get("port", 5432)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": DB_NAME,
        "USER": DB_USER,
        "PASSWORD": DB_PASSWORD,
        "HOST": DB_HOST,
        "PORT": DB_PORT,
        "OPTIONS": {"sslmode": "require"},
    }
}



# ------------------------------
# AWS S3 / MinIO helper (optional)
# ------------------------------
USE_S3 = secrets.get("USE_S3", False)
AWS_REGION = secrets.get("AWS_REGION", "ap-southeast-2")
AWS_STORAGE_BUCKET_NAME = secrets.get("AWS_STORAGE_BUCKET_NAME")
AWS_S3_ENDPOINT_URL = secrets.get("AWS_S3_ENDPOINT_URL")

if USE_S3:
    def get_s3_client():
        """Return an S3 client for AWS or MinIO."""
        session = boto3.Session(region_name=AWS_REGION)
        return session.client("s3", endpoint_url=AWS_S3_ENDPOINT_URL)

# ------------------------------
# Cognito configuration
# ------------------------------
COGNITO_REGION = secrets.get("COGNITO_REGION", "ap-southeast-2")
COGNITO_USER_POOL_ID = secrets.get("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = secrets.get("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = secrets.get("COGNITO_CLIENT_SECRET")
COGNITO_ADMIN_GROUP = secrets.get("COGNITO_ADMIN_GROUP", "admin")

# ------------------------------
# Sessions & security settings
# ------------------------------
SESSION_COOKIE_AGE = 7 * 24 * 60 * 60  # 7 days
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False") == "True"
CSRF_COOKIE_SECURE = os.environ.get("CSRF_COOKIE_SECURE", "False") == "True"

# ------------------------------
# Static & media files configuration
# ------------------------------
STATIC_URL = '/static/'
MEDIA_URL = '/media/'
STATICFILES_DIRS = [os.path.join(BASE_DIR, 'static')]
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# ------------------------------
# Cognito token refresh margin
# ------------------------------
COGNITO_TOKEN_REFRESH_MARGIN = 300  # Seconds before expiry to refresh token
