import os
import json
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------
# AWS Secrets Manager function
# ------------------------------
def get_secrets(secret_name, region_name="ap-southeast-2"):
    """Retrieve all secrets from AWS Secrets Manager"""
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret_string = response.get("SecretString", "")
        if not secret_string:
            raise ValueError(f"No secret found for {secret_name}")
        return json.loads(secret_string)
    except ClientError as e:
        print(f"Error retrieving secret {secret_name}: {e}")
        raise e

# Fetch secrets from Secrets Manager
secrets = get_secrets(secret_name="n11605618-a2RDSecret")

# Map secrets to Django expected variables
SECRET_KEY = secrets["SECRET_KEY"]
DB_USER = secrets["username"]
DB_PASSWORD = secrets["password"]
DB_NAME = secrets["dbname"]
DB_HOST = secrets["host"]
DB_PORT = secrets["port"]

# ------------------------------
# Django core settings
# ------------------------------
DEBUG = True  # Set to False in production
ALLOWED_HOSTS = ["*"]

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
# Database
# ------------------------------
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
# Cache (ElastiCache Memcached with fallback)
# ------------------------------
DEFAULT_MEMCACHED_ENDPOINT = "127.0.0.1:11211"  # fallback if ElastiCache fails
MEMCACHED_ENDPOINT = secrets.get("MEMCACHED_ENDPOINT", DEFAULT_MEMCACHED_ENDPOINT)

if ":" in MEMCACHED_ENDPOINT:
    MEMCACHED_HOST, MEMCACHED_PORT = MEMCACHED_ENDPOINT.split(":")
    MEMCACHED_PORT = int(MEMCACHED_PORT)
else:
    MEMCACHED_HOST = MEMCACHED_ENDPOINT
    MEMCACHED_PORT = 11211

def get_cache_location():
    import socket
    try:
        sock = socket.create_connection((MEMCACHED_HOST, MEMCACHED_PORT), timeout=1)
        sock.close()
        print(f"[INFO] Connected to Memcached at {MEMCACHED_HOST}:{MEMCACHED_PORT}")
        return f"{MEMCACHED_HOST}:{MEMCACHED_PORT}"
    except Exception as e:
        print(f"[WARNING] Cannot connect to Memcached at {MEMCACHED_HOST}:{MEMCACHED_PORT}, falling back: {e}")
        return DEFAULT_MEMCACHED_ENDPOINT

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.memcached.PyMemcacheCache",
        "LOCATION": get_cache_location(),
    }
}

# ------------------------------
# AWS S3 (optional)
# ------------------------------
USE_S3 = secrets.get("USE_S3", False)
AWS_REGION = secrets.get("AWS_REGION", "ap-southeast-2")
AWS_STORAGE_BUCKET_NAME = secrets.get("AWS_STORAGE_BUCKET_NAME")
AWS_S3_ENDPOINT_URL = secrets.get("AWS_S3_ENDPOINT_URL")

if USE_S3:
    def get_s3_client():
        session = boto3.Session(region_name=AWS_REGION)
        return session.client("s3", endpoint_url=AWS_S3_ENDPOINT_URL)

# ------------------------------
# Cognito config
# ------------------------------
COGNITO_REGION = secrets.get("COGNITO_REGION", "ap-southeast-2")
COGNITO_USER_POOL_ID = secrets.get("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = secrets.get("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = secrets.get("COGNITO_CLIENT_SECRET")
COGNITO_ADMIN_GROUP = secrets.get("COGNITO_ADMIN_GROUP", "admin")

print(f"[DEBUG] Cognito config loaded: "
      f"region={COGNITO_REGION}, pool={COGNITO_USER_POOL_ID}, client_id={COGNITO_CLIENT_ID}")

# ------------------------------
# Static files
# ------------------------------
STATIC_URL = "/static/"

# For development (optional)
STATICFILES_DIRS = [
    BASE_DIR / "static",
]

# For collectstatic in production
STATIC_ROOT = BASE_DIR / "staticfiles"
