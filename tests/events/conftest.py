from collections import namedtuple

import pytest


@pytest.fixture()
def wsgi_request():
    return namedtuple("Request", ["environ", "user", "session"])(
        {"REMOTE_ADDR": "192.168.1.101", "SERVER_NAME": "WebServer.local"},
        namedtuple("User", ["username"])("Adrian"),
        namedtuple("Session", ["session_key"])("def456"),
    )
