from importlib import reload
import os

import ddtrace
import django


def pytest_configure(config):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
    os.environ["DD_ENV"] = "test"
    os.environ["DD_SERVICE"] = "django-service"
    os.environ["DD_VERSION"] = "1.0.0"
    os.environ["ECS_CONTAINER_METADATA_URI"] = (
        "http://169.254.170.2/v3/709d1c10779d47b2a84db9eef2ebd041-0265927825"
    )
    reload(ddtrace)

    django.setup()
