from decouple import config
from pathlib import Path
from datetime import timedelta
import dj_database_url
import os

import environ

env = environ.Env()

environ.Env.read_env()


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-f*$dp9#im)nkbux#8lml8j#wn^1jvtxu6tb6%&k47f+inid09-"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ["*"]

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
    "logs",
    "departments",
    "roles",
    "verifications",
    "data_uploads",
    "security_logs",
    "permissions",
    "accounts_mobile",
    "products",
    "admin_rosolutions",
    # third party packages
    "drf_yasg",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "rest_framework_simplejwt",
    "django_filters",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    # -------CORS-----
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    # -------CORS-----
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]


ROOT_URLCONF = "api.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "api.wsgi.application"

# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

# DATABASES = {
#     "default": {
#         "ENGINE": "django.db.backends.sqlite3",
#         "NAME": BASE_DIR / "db.sqlite3",
#     }
# }

DATABASES = {"default": dj_database_url.parse(env("DATABASE_URL"))}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Africa/Lagos"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

MEDIA_URL = "/media/"

MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


AUTH_USER_MODEL = "accounts.CustomUser"

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True

# email settings
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
RESEND_SMTP_PORT = 587
RESEND_SMTP_USERNAME = "resend"
RESEND_SMTP_HOST = "smtp.resend.com"
RESEND_SMTP_PASSWORD = "re_64KjvwsN_QFkge5aXMi696jbuKjErihST"
DEFAULT_FROM_EMAIL = "verify@cvmsnigeria.com"
RESEND_API_KEY = "re_64KjvwsN_QFkge5aXMi696jbuKjErihST"


# REST_FRAMEWORK = {
#     'DEFAULT_AUTHENTICATION_CLASSES': (
#         'accounts.custom_jwt_auth.CustomJWTAuthentication',
#     ),
# }


SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "BLACKLIST_AFTER_ROTATION": True,
    "ROTATE_REFRESH_TOKENS": True,
}

# Admin email
ADMINS = [
    ("Super Administrator", "super_admin@cvms.com"),
]


STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
    },
}

# JAZZMIN_SETTINGS = {
#     "site_title": "CVMS dashboard",
#     "site_header": "CVMS",
#     "site_brand": "CVMS",
#     "site_logo": "",
#     "login_logo": None,
#     "login_logo_dark": None,
#     "site_logo_classes": "img-circle",
#     "site_icon": None,
#     "welcome_sign": "Welcome to the CVMS",
#     "copyright": "Afripoint Group",
#     "search_model": ["auth.User", "auth.Group"],
#     "user_avatar": None,
#     # Whether to display the side menu
#     "show_sidebar": True,
#     # Whether to aut expand the menu
#     "navigation_expanded": True,
#     # Hide these apps when generating side menu e.g (auth)
#     "hide_apps": [],
#     # Hide these models when generating side menu (e.g auth.user)
#     "hide_models": [],
#     #################
#     # Related Modal #
#     #################
#     # Use modals instead of popups
#     "related_modal_active": False,
# }
