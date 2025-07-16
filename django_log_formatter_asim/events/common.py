from enum import Enum
from typing import Optional
from typing import TypedDict

from django.http import HttpRequest


class Result(str, Enum):
    Success = "Success"
    Partial = "Partial"
    Failure = "Failure"
    NA = "NA"


class Severity(str, Enum):
    Informational = "Informational"
    Low = "Low"
    Medium = "Medium"
    High = "High"


class Client(TypedDict):
    """Dictionary to represent properties of the HTTP Client."""

    """Internet Protocol Address of the client making the Authentication
    event."""
    ip_address: Optional[str]
    """URL requested by the client."""
    requested_url: Optional[str]


class Server(TypedDict):
    """Dictionary to represent properties of the HTTP Server."""

    """
    A unique identifier for the server which serviced the Authentication event.

    Defaults to the WSGI HTTP_HOST field if not provided.
    """
    hostname: Optional[str]
    """Internet Protocol Address of the server serving this request."""
    ip_address: Optional[str]


def _default_severity(result: Result) -> Severity:
    return Severity.Informational if result == Result.Success else Severity.Medium


def _get_client_ip_address(request: HttpRequest) -> Optional[str]:
    # Import here as ipware uses settings
    from ipware import get_client_ip

    client_ip, _ = get_client_ip(request)
    return client_ip
