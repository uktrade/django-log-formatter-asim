import datetime
import json
from enum import Enum
from hashlib import sha3_512
from typing import Literal
from typing import Optional
from typing import TypedDict

from django.http import HttpRequest

from .common import Activity
from .common import Client
from .common import Result
from .common import Server
from .common import Severity


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


class LogAuthentication(Activity):
    Event = AuthenticationEvent
    Result = Result
    LoginMethod = AuthenticationLoginMethod
    Severity = Severity

    def __call__(
        self,
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

        self._log_authentication(
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
        self,
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
            "EventOriginalType": self._event_code(event, result),
            "EventType": event,
            "LogonMethod": login_method,
            "EventSchema": "Authentication",
            "EventSchemaVersion": "0.1.4",
        }

        log.update(
            self._activity_fields(
                request, event_created, result, server, client, severity, result_details, message
            )
        )

        if "role" in user:
            log["TargetUserType"] = user["role"]

        if "sessionId" in user:
            log["TargetSessionId"] = self._cryptographically_hash(user["sessionId"])
        elif hasattr(request, "session") and request.session.session_key:
            log["TargetSessionId"] = self._cryptographically_hash(request.session.session_key)

        if "username" in user:
            log["TargetUsername"] = user["username"]
        elif hasattr(request, "user") and request.user.username:
            log["TargetUsername"] = request.user.username

        print(json.dumps(log), flush=True)

    def _cryptographically_hash(self, data: Optional[str]) -> Optional[str]:
        if data is None:
            return None
        return sha3_512(data.encode("UTF-8")).hexdigest()

    def _event_code(self, event: AuthenticationEvent, result: Result) -> str:
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
