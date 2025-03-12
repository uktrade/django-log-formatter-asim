from importlib import reload
import os

import ddtrace
import django


def pytest_configure(config):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
    os.environ["DD_ENV"] = "test"
    os.environ["DD_SERVICE"] = "django-service"
    os.environ["DD_VERSION"] = "1.0.0"
    reload(ddtrace)

    django.setup()
