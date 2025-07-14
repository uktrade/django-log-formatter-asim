from collections import namedtuple

from django_log_formatter_asim.events.common import _get_client_ip_address


def test_get_client_ip_address_uses_X_FORWARDED_FOR():
    wsgi_request = namedtuple("Request", ["META"])(
        {
            "X_FORWARDED_FOR": "90.243.238.50, 130.176.222.238, 127.0.0.1",
        },
    )

    assert _get_client_ip_address(wsgi_request) == "90.243.238.50"
