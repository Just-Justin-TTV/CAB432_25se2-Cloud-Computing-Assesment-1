import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()


# =======================
# Base settings
# =======================
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret")
DEBUG = os.environ.get("DEBUG", "True") == "True"
ALLOWED_HOSTS = ["*"]  # adjust for production

# =======================
# Installed apps
# =======================
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
    'storages',  # S3 storage
]

# =======================
# Middleware
# =======================
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_browser_reload.middleware.BrowserReloadMiddleware',
]

ROOT_URLCONF = 'app1.urls'

# =======================
# Templates
# =======================
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

# =======================
# Database configuration from environment
# =======================
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "cohort_2025"),
        "USER": os.environ.get("DB_USER", "s381"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "hQ5o87dNk9mx"),
        "HOST": os.environ.get(
            "DB_HOST",
            "database-1-instance-1.ce2haupt2cta.ap-southeast-2.rds.amazonaws.com",
        ),
        "PORT": os.environ.get("DB_PORT", "5432"),
        "OPTIONS": {"sslmode": os.environ.get("DB_SSLMODE", "require")},
    }
}

# =======================
# Password validation
# =======================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

APPEND_SLASH = False

# =======================
# Internationalization
# =======================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# =======================
# Static & Media
# =======================
STATIC_URL = 'static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

TAILWIND_APP_NAME = 'theme'
INTERNAL_IPS = ["127.0.0.1"]

# =======================
# AWS S3 Configuration
# =======================
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_SESSION_TOKEN = os.environ.get("AWS_SESSION_TOKEN", None)  # optional for temporary creds
AWS_S3_BUCKET_NAME = "justinsinghatwalbucket"
AWS_S3_REGION_NAME = "ap-southeast-2"
AWS_S3_CUSTOM_DOMAIN = f"{AWS_S3_BUCKET_NAME}.s3.{AWS_S3_REGION_NAME}.amazonaws.com"

# Optional folder prefixes
AWS_S3_RESUME_FOLDER = "resumes"
AWS_S3_FEEDBACK_FOLDER = "feedback"

# Use S3 as the default storage for media files
DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

# Base URL for media files
MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/"

# Optional: organize files into folders automatically
AWS_LOCATION = ""  # can leave blank if your models specify folders
