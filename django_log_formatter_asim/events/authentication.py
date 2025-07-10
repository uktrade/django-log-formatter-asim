import datetime
import json
from enum import Enum
from typing import Literal
from typing import Optional
from typing import TypedDict

from django.http import HttpRequest

from .common import Client
from .common import Result
from .common import Server
from .common import Severity
from .common import _default_severity


class AuthenticationEvent(str, Enum):
    Logon = "Logon"
    Logoff = "Logoff"


class AuthenticationLoginMethod(str, Enum):
    UsernamePassword = "Username & Password"
    StaffSSO = "Staff-SSO"
    UKGOVSSO = "UK.GOV-SSO"
    ExternalIDP = "External IdP"


class AuthenticationUser(TypedDict):
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
                        - Server hostname
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
    if user == None:
        user = {}
    if server == None:
        server = {}
    if client == None:
        client = {}

    event_created = time_generated or datetime.datetime.now(tz=datetime.timezone.utc)

    log = {
        "EventCreated": event_created.isoformat(),  # TODO: Should this really be EventCreated, or TimeGenerated
        "EventSeverity": severity or _default_severity(result),
        "EventOriginalType": _event_code(event, result),
        "EventType": event,
        "EventResult": result,
        "LogonMethod": login_method,
        "EventSchema": "Authentication",
        "EventSchemaVersion": "0.1.4",
    }

    if "hostname" in server:
        log["DvcHostname"] = server["hostname"]
    elif hasattr(request, "environ") and "SERVER_NAME" in request.environ:
        log["DvcHostname"] = request.environ["SERVER_NAME"]

    if "ip_address" in client:
        log["SrcIpAddr"] = client["ip_address"]
    elif hasattr(request, "environ") and "REMOTE_ADDR" in request.environ:
        log["SrcIpAddr"] = request.environ.get("REMOTE_ADDR")

    if "role" in user:
        log["ActorUserType"] = user["role"]

    if "sessionId" in user:
        log["ActorSessionId"] = user["sessionId"]
    elif request.session.session_key:
        log["ActorSessionId"] = request.session.session_key

    if "username" in user:
        log["ActorUsername"] = user["username"]
    elif request.user.username:
        log["ActorUsername"] = request.user.username

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
