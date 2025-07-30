import datetime
import json
import os
from enum import Enum
from hashlib import sha3_512
from typing import Literal
from typing import Optional
from typing import TypedDict

from django.http import HttpRequest

from django_log_formatter_asim.ecs import _get_container_id

from .common import Client
from .common import Result
from .common import Server
from .common import Severity
from .common import _default_severity
from .common import _get_client_ip_address


class AuthenticationEvent(str, Enum):
    Logon = "Logon"
    Logoff = "Logoff"


class AuthenticationLoginMethod(str, Enum):
    UsernamePassword = "Username & Password"
    StaffSSO = "Staff-SSO"
    UKGOVSSO = "UK.GOV-SSO"
    ExternalIDP = "External IdP"


class AuthenticationUser(TypedDict, total=False):
    """Dictionary to represent properties of the users session."""

    """What type of role best describes this Authentication event."""
    role: Optional[
        Literal[
            "Regular",
            "Machine",
            "Admin",
            "System",
            "Application",
            "Service Principal",
            "Service",
            "Anonymous",
            "Other",
        ]
    ]
    """
    A unique identifier for the user.

    Defaults to the logged in Django User.username if not provided.
    """
    username: Optional[str]
    """
    A unique identifier for this authentication session if one exists.

    Defaults to the Django Sessions session key if not provided.
    """
    sessionId: Optional[str]


def log_authentication(
    request: HttpRequest,
    event: AuthenticationEvent,
    result: Result,
    login_method: AuthenticationLoginMethod,
    user: Optional[AuthenticationUser] = None,
    server: Optional[Server] = None,
    client: Optional[Client] = None,
    severity: Optional[Severity] = None,
    time_generated: Optional[datetime.datetime] = None,
    result_details: Optional[str] = None,
    message: Optional[str] = None,
):
    """
    Log an ASIM Authentication Event to standard output.

    :param request: django.http.HttpRequest object which initiated this Authentication request
                    from which the following data will be logged if available
                        - Django Authentication systems current username
                        - Django Session middlewares Session Key
                        - Client IP address
                        - URL requested by the client
                        - Server domain name
    :param event: What authentication action was attempted, either "Logon" or "Logoff"
    :param result: What outcome did the action have, either "Success", "Failure", "Partial", "NA"
    :param login_method: What authentication mechanism was being used, one of:
                        - "Username & Password"
                        - "Staff-SSO"
                        - "UK.GOV-SSO"
                        - "External IdP"
    :param user: Dictionary containing information on the subject of this Authentication event
                 see AuthenticationUser class for more details.
    :param server: Dictionary containing information on the server servicing this Authentication event
                   see Server class for more details.
    :param client: Dictionary containing information on the client performing this Authentication event
                   see Client class for more details.
    :param severity: Optional severity of the event, defaults to "Informational", otherwise one of:
                        - "Informational"
                        - "Low"
                        - "Medium"
                        - "High"
    :param time_generated: Optional datetime for when the event happened, otherwise datetime.now
    :param result_details: Optional string describing any details associated with the events outcome.
                           This field is typically populated when the result is a failure.
    :param message: Optional string describing the reason why the log was generated.

    See also: https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-authentication
    """

    _log_authentication(
        request,
        event,
        result,
        login_method,
        user={} if user == None else user,
        server={} if server == None else server,
        client={} if client == None else client,
        event_created=time_generated or datetime.datetime.now(tz=datetime.timezone.utc),
        severity=severity,
        result_details=result_details,
        message=message,
    )


def _log_authentication(
    request: HttpRequest,
    event: AuthenticationEvent,
    result: Result,
    login_method: AuthenticationLoginMethod,
    user: AuthenticationUser,
    server: Server,
    client: Client,
    event_created: datetime.datetime,
    severity: Optional[Severity] = None,
    result_details: Optional[str] = None,
    message: Optional[str] = None,
):
    log = {
        "EventStartTime": event_created.isoformat(),
        "EventSeverity": severity or _default_severity(result),
        "EventOriginalType": _event_code(event, result),
        "EventType": event,
        "EventResult": result,
        "LogonMethod": login_method,
        "EventSchema": "Authentication",
        "EventSchemaVersion": "0.1.4",
    }

    if "domain_name" in server:
        log["HttpHost"] = server["domain_name"]
    elif "HTTP_HOST" in request.META:
        log["HttpHost"] = request.get_host()

    if "service_name" in server:
        log["TargetAppName"] = server["service_name"]
    elif os.environ.get("COPILOT_APPLICATION_NAME") and os.environ.get("COPILOT_SERVICE_NAME"):
        app_name = f"{os.environ['COPILOT_APPLICATION_NAME']}-{os.environ['COPILOT_SERVICE_NAME']}"
        log["TargetAppName"] = app_name

    if container_id := _get_container_id():
        log["TargetContainerId"] = container_id

    if "ip_address" in client:
        log["SrcIpAddr"] = client["ip_address"]
    elif client_ip := _get_client_ip_address(request):
        log["SrcIpAddr"] = client_ip

    if "requested_url" in client:
        log["TargetUrl"] = client["requested_url"]
    elif "HTTP_HOST" in request.META:
        log["TargetUrl"] = request.scheme + "://" + request.get_host() + request.get_full_path()

    if "role" in user:
        log["TargetUserType"] = user["role"]

    if "sessionId" in user:
        log["TargetSessionId"] = _cryptographically_hash(user["sessionId"])
    elif hasattr(request, "session") and request.session.session_key:
        log["TargetSessionId"] = _cryptographically_hash(request.session.session_key)

    if "username" in user:
        log["TargetUsername"] = user["username"]
    elif hasattr(request, "user") and request.user.username:
        log["TargetUsername"] = request.user.username

    if result_details:
        log["EventResultDetails"] = result_details

    if message:
        log["EventMessage"] = message

    if "ip_address" in server:
        log["DvcIpAddr"] = server["ip_address"]

    print(json.dumps(log), flush=True)


log_authentication.Event = AuthenticationEvent
log_authentication.Result = Result
log_authentication.LoginMethod = AuthenticationLoginMethod
log_authentication.Severity = Severity


def _cryptographically_hash(data: Optional[str]) -> Optional[str]:
    if data is None:
        return None
    return sha3_512(data.encode("UTF-8")).hexdigest()


def _event_code(event: AuthenticationEvent, result: Result) -> str:
    if event == AuthenticationEvent.Logon:
        if result == Result.Success:
            return "001a"
        elif result == Result.Failure:
            return "001b"
    elif event == AuthenticationEvent.Logoff:
        if result == Result.Success:
            return "001c"
        elif result == Result.Failure:
            return "001d"
    return "001"
