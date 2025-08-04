import datetime
import json
from enum import Enum
from typing import Optional
from typing import TypedDict

from django.http import HttpRequest

from .common import Activity
from .common import Client
from .common import LoggedInUser
from .common import Result
from .common import Server
from .common import Severity


class FileActivityEvent(str, Enum):
    UserCreated = "UserCreated"
    UserDeleted = "UserDeleted"
    UserModified = "UserModified"
    UserLocked = "UserLocked"
    UserUnlocked = "UserUnlocked"
    UserDisabled = "UserDisabled"
    UserEnabled = "UserEnabled"
    PasswordChanged = "PasswordChanged"
    PasswordReset = "PasswordReset"
    GroupCreated = "GroupCreated"
    GroupDeleted = "GroupDeleted"
    GroupModified = "GroupModified"
    UserAddedToGroup = "UserAddedToGroup"
    UserRemovedFromGroup = "UserRemovedFromGroup"
    GroupEnumerated = "GroupEnumerated"
    UserRead = "UserRead"
    GroupRead = "GroupRead"


class Account(TypedDict, total=False):
    """Dictionary to represent details of the account management event."""

    """
    If a user was managed, the username of that user
    """
    username: Optional[str]
    """If a group was managed, the name of the group."""
    group: Optional[str]
    """
    If the Account Management event is one of the following.

    - UserModified
    - GroupModified

    Details of the property which was changed, in the form:
        ("propertyName", "oldValue", "newValue")
    """
    changed: tuple[str, str, str]


class LogAccountManagement(Activity):
    Event = FileActivityEvent
    Result = Result
    Severity = Severity

    def __call__(
        self,
        request: HttpRequest,
        event: Event,
        account: Account,
        result: Result,
        user: Optional[LoggedInUser] = None,
        server: Optional[Server] = None,
        client: Optional[Client] = None,
        severity: Optional[Severity] = None,
        time_generated: Optional[datetime.datetime] = None,
        result_details: Optional[str] = None,
        message: Optional[str] = None,
    ):
        self._log_account_management(
            request,
            event,
            account,
            result,
            {} if user == None else user,
            {} if server == None else server,
            {} if client == None else client,
            time_generated or datetime.datetime.now(tz=datetime.timezone.utc),
            severity,
            result_details,
            message,
        )

    def _log_account_management(
        self,
        request: HttpRequest,
        event: Event,
        account: Account,
        result: Result,
        user: LoggedInUser,
        server: Server,
        client: Client,
        event_created: datetime.datetime,
        severity: Optional[Severity] = None,
        result_details: Optional[str] = None,
        message: Optional[str] = None,
    ):
        log = {
            "EventSchema": "UserManagement",
            "EventSchemaVersion": "0.1.1",
            "EventType": event,
        }
        log.update(
            self._activity_fields(
                request, event_created, result, server, client, severity, result_details, message
            )
        )

        if "username" in user:
            log["ActorUsername"] = user["username"]
        elif hasattr(request, "user") and request.user.username:
            log["ActorUsername"] = request.user.username

        if "username" in account:
            log["TargetUsername"] = account["username"]

        if "group" in account:
            log["GroupName"] = account["group"]

        if "changed" in account:
            (propertyName, previousPropertyValue, newPropertyName) = account["changed"]
            log["UpdatedPropertyName"] = propertyName
            log["PreviousPropertyValue"] = previousPropertyValue
            log["NewPropertyValue"] = newPropertyName

        print(json.dumps(log), flush=True)
