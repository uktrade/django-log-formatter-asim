from collections import namedtuple

import pytest
from django.test import RequestFactory


@pytest.fixture()
def wsgi_request():
    factory = RequestFactory()
    request = factory.get(
        "/steel", secure=True, **{"REMOTE_ADDR": "192.168.1.101", "HTTP_HOST": "WebServer.local"}
    )

    request.user = namedtuple("User", ["username"])("Adrian")
    request.session = namedtuple("Session", ["session_key"])("def456")

    return request
