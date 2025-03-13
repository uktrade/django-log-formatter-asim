import os

import django


def pytest_configure(config):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
    os.environ["ECS_CONTAINER_METADATA_URI"] = (
        "http://169.254.170.2/v3/709d1c10779d47b2a84db9eef2ebd041-0265927825"
    )

    django.setup()
