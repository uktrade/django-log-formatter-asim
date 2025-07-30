import datetime
import os
from enum import Enum
from typing import Optional
from typing import TypedDict

from django.http import HttpRequest

from django_log_formatter_asim.ecs import _get_container_id


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


class Client(TypedDict, total=False):
    """Dictionary to represent properties of the HTTP Client."""

    """Internet Protocol Address of the client making the Authentication
    event."""
    ip_address: Optional[str]
    """URL requested by the client."""
    requested_url: Optional[str]


class Server(TypedDict, total=False):
    """Dictionary to represent properties of the HTTP Server."""

    """
    The FQDN that this server is listening to HTTP requests on. For example:
        web.trade.gov.uk

    Defaults to the WSGI HTTP_HOST field if not provided.
    """
    domain_name: Optional[str]
    """Internet Protocol Address of the server serving this request."""
    ip_address: Optional[str]
    """
    A unique (within DBT) identifier for the software running on the server.
    For example: berry-auctions-frontend

    Defaults to combining the environment variables COPILOT_APPLICATION_NAME and
    COPILOT_SERVICE_NAME separated by a '-'.
    """
    service_name: Optional[str]


class Activity:
    def _activity_fields(
        self,
        request: HttpRequest,
        event_created: datetime.datetime,
        result: Result,
        server: Server,
        client: Client,
        severity: Optional[Severity],
        result_details: Optional[str],
        message: Optional[str],
    ):
        log = {
            "EventStartTime": event_created.isoformat(),
            "EventSeverity": severity or self._default_severity(result),
            "EventResult": result,
        }

        if "domain_name" in server:
            log["HttpHost"] = server["domain_name"]
        elif "HTTP_HOST" in request.META:
            log["HttpHost"] = request.get_host()

        if "service_name" in server:
            log["TargetAppName"] = server["service_name"]
        elif os.environ.get("COPILOT_APPLICATION_NAME") and os.environ.get("COPILOT_SERVICE_NAME"):
            app_name = (
                f"{os.environ['COPILOT_APPLICATION_NAME']}-{os.environ['COPILOT_SERVICE_NAME']}"
            )
            log["TargetAppName"] = app_name

        if container_id := _get_container_id():
            log["TargetContainerId"] = container_id

        if "ip_address" in client:
            log["SrcIpAddr"] = client["ip_address"]
        elif client_ip := self._get_client_ip_address(request):
            log["SrcIpAddr"] = client_ip

        if "requested_url" in client:
            log["TargetUrl"] = client["requested_url"]
        elif "HTTP_HOST" in request.META:
            log["TargetUrl"] = request.scheme + "://" + request.get_host() + request.get_full_path()

        if result_details:
            log["EventResultDetails"] = result_details

        if message:
            log["EventMessage"] = message

        if "ip_address" in server:
            log["DvcIpAddr"] = server["ip_address"]

        return log

    def _default_severity(sef, result: Result) -> Severity:
        return Severity.Informational if result == Result.Success else Severity.Medium

    def _get_client_ip_address(self, request: HttpRequest) -> Optional[str]:
        # Import here as ipware uses settings
        from ipware import get_client_ip

        client_ip, _ = get_client_ip(request)
        return client_ip
