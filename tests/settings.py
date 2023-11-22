import sys

from django_log_formatter_asim import ASIMFormatter

SECRET_KEY = "fake-key"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "asim_formatter": {
            "()": ASIMFormatter,
        },
    },
    "handlers": {
        "asim": {
            "class": "logging.StreamHandler",
            "formatter": "asim_formatter",
        },
        "stdout": {
            "class": "logging.StreamHandler",
            "stream": sys.stdout,
        },
    },
    "root": {
        "handlers": ["stdout"],
        "level": "DEBUG",
    },
    "loggers": {
        "django": {
            "handlers": [
                "asim",
                "stdout",
            ],
            "level": "DEBUG",
            "propagate": True,
        },
        "django.request": {
            "handlers": [
                "asim",
                "stdout",
            ],
            "level": "DEBUG",
            "propagate": True,
        },
    },
}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
]

USE_TZ = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "db.sqlite3",
    }
}
