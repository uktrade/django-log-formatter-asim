import datetime
import json
import os
from enum import Enum
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


class FileActivityEvent(str, Enum):
    FileAccessed = "FileAccessed"
    FileCreated = "FileCreated"
    FileModified = "FileModified"
    FileDeleted = "FileDeleted"
    FileRenamed = "FileRenamed"
    FileCopied = "FileCopied"
    FileMoved = "FileMoved"
    FolderCreated = "FolderCreated"
    FolderDeleted = "FolderDeleted"
    FolderMoved = "FolderMoved"
    FolderModified = "FolderModified"


class FileActivityFileBase(TypedDict):
    """Mandatory field definitions of FileActivityFile."""

    """
    The full, normalized path of the target file, including the folder or
    location, the file name, and the extension.
    """
    path: str


class FileActivityFile(FileActivityFileBase, total=False):
    """Dictionary to represent properties of either the target or source
    file."""

    """
    The name of the target file, without a path or a location, but with an
    extension if available. This field should be similar to the final element in
    the *FilePath field.

    Defaults to extracting the name based off the path if not provided.
    """
    name: Optional[str]
    """
    The file extension.

    Defaults to extracting the extension based off the path if not provided.
    """
    extension: Optional[str]
    """
    The Mime, or Media, type of the target file.

    Allowed values are listed in the IANA Media Types repository.
    """
    content_type: Optional[str]
    """The SHA256 value of the file."""
    sha256: Optional[str]
    """The size of the file in bytes."""
    size: Optional[int]


class FileActivityUser(TypedDict, total=False):
    """
    A unique identifier for the user.

    Defaults to the logged in Django User.username if not provided.
    """

    username: Optional[str]


class LogFileActivity:
    Event = FileActivityEvent
    Result = Result
    Severity = Severity

    def __call__(
        self,
        request: HttpRequest,
        event: FileActivityEvent,
        result: Result,
        file: FileActivityFile,
        source_file: Optional[FileActivityFile] = None,
        user: Optional[FileActivityUser] = None,
        server: Optional[Server] = None,
        client: Optional[Client] = None,
        severity: Optional[Severity] = None,
        time_generated: Optional[datetime.datetime] = None,
        result_details: Optional[str] = None,
        message: Optional[str] = None,
    ):
        """
        Log an ASIM File Event to standard output.

        :param request: django.http.HttpRequest object which initiated this Authentication request
                        from which the following data will be logged if available
                            - Django Authentication systems current username
                            - Client IP address
                            - URL requested by the client
                            - Server domain name
        :param event: What File Event action was attempted, one of:
                            - FileAccessed
                            - FileCreated
                            - FileModified
                            - FileDeleted
                            - FileRenamed
                            - FileCopied
                            - FileMoved
                            - FolderCreated
                            - FolderDeleted
                            - FolderMoved
                            - FolderModified
        :param result: What outcome did the action have, either "Success", "Failure", "Partial", "NA"
        :param file: Dictionary containing information on the target of this File event see
                    FileActivityFile for more details.
        :param source_file: Dictionary containing information on the source of this File event,
                            this MUST be used for a FileRenamed, FileMoved, FileCopied, FolderMoved
                            operation. See FileActivityFile for more details.
        :param user: Dictionary containing information on the logged in users username.
        :param server: Dictionary containing information on the server servicing this File event
                    see Server class for more details.
        :param client: Dictionary containing information on the client performing this File event
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

        See also: https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-file-event
        """

        self._log_file_activity(
            request,
            event,
            result,
            file,
            source_file,
            user={} if user == None else user,
            server={} if server == None else server,
            client={} if client == None else client,
            event_created=time_generated or datetime.datetime.now(tz=datetime.timezone.utc),
            severity=severity,
            result_details=result_details,
            message=message,
        )

    def _log_file_activity(
        self,
        request: HttpRequest,
        event: FileActivityEvent,
        result: Result,
        file: FileActivityFile,
        source_file: Optional[FileActivityFile],
        user: FileActivityUser,
        server: Server,
        client: Client,
        event_created: datetime.datetime,
        severity: Optional[Severity] = None,
        result_details: Optional[str] = None,
        message: Optional[str] = None,
    ):
        log = {
            "EventSchema": "FileEvent",
            "EventSchemaVersion": "0.2.1",
            "EventType": event,
            "EventResult": result,
            "EventStartTime": event_created.isoformat(),
            "EventSeverity": severity or _default_severity(result),
        }

        log.update(self._generate_file_attributes(file, "Target"))
        if source_file:
            log.update(self._generate_file_attributes(source_file, "Src"))

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
        elif client_ip := _get_client_ip_address(request):
            log["SrcIpAddr"] = client_ip

        if "requested_url" in client:
            log["TargetUrl"] = client["requested_url"]
        elif "HTTP_HOST" in request.META:
            log["TargetUrl"] = request.scheme + "://" + request.get_host() + request.get_full_path()

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

    def _generate_file_attributes(self, file: FileActivityFile, prefix: str) -> dict:
        log = {prefix + "FilePath": file["path"]}

        if "name" in file:
            log[prefix + "FileName"] = file["name"]
        else:
            log[prefix + "FileName"] = os.path.basename(file["path"])

        if "extension" in file:
            log[prefix + "FileExtension"] = file["extension"]
        else:
            file_name_parts = list(filter(None, log[prefix + "FileName"].split(".", 1)))
            if len(file_name_parts) > 1:
                log[prefix + "FileExtension"] = file_name_parts[1]

        if "content_type" in file:
            log[prefix + "FileMimeType"] = file["content_type"]

        if "sha256" in file:
            log[prefix + "FileSHA256"] = file["sha256"]

        if "size" in file:
            log[prefix + "FileSize"] = file["size"]

        return log
