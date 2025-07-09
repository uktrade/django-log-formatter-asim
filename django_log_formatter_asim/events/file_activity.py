import datetime
import json
import os
from enum import Enum
from typing import Optional
from typing import TypedDict

from django.http import HttpRequest

from .common import Client
from .common import Result
from .common import Server
from .common import Severity
from .common import _default_severity


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


class FileActivityFile(TypedDict):
    """Dictionary to represent properties of the target file."""

    """
    The full, normalized path of the target file, including the folder or location,
    the file name, and the extension.
    """
    path: str
    """
    The name of the target file, without a path or a location, but with an
    extension if available. This field should be similar to the final element in
    the TargetFilePath field.

    Defaults to extracting the name based off the path if not provided.
    """
    name: Optional[str]
    """
    The target file extension.

    Defaults to extracting the extension based off the path if not provided.
    """
    extension: Optional[str]
    """
    The Mime, or Media, type of the target file.

    Allowed values are listed in the IANA Media Types repository.
    """
    content_type: Optional[str]
    """The SHA256 value of the target file."""
    sha256: Optional[str]
    """The size of the target file in bytes."""
    size: Optional[int]


class FileActivityUser(TypedDict):
    """
    A unique identifier for the user.

    Defaults to the logged in Django User.username if not provided.
    """

    username: Optional[str]


def log_file_activity(
    request: HttpRequest,
    event: FileActivityEvent,
    result: Result,
    file: FileActivityFile,
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
                        - Server hostname
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
    if user == None:
        user = {}
    if server == None:
        server = {}
    if client == None:
        client = {}

    event_created = time_generated or datetime.datetime.now(tz=datetime.timezone.utc)

    log = {
        "EventSchema": "FileEvent",
        "EventSchemaVersion": "0.2.1",
        "EventType": event,
        "EventResult": result,
        "EventCreated": event_created.isoformat(),  # TODO: Should this really be EventCreated, or TimeGenerated
        "EventSeverity": severity or _default_severity(result),
        "TargetFilePath": file["path"],
    }

    if "name" in file:
        log["TargetFileName"] = file["name"]
    else:
        log["TargetFileName"] = os.path.basename(file["path"])

    if "extension" in file:
        log["TargetFileExtension"] = file["extension"]
    else:
        file_name_parts = list(filter(None, log["TargetFileName"].split(".", 1)))
        if len(file_name_parts) > 1:
            log["TargetFileExtension"] = file_name_parts[1]

    if "content_type" in file:
        log["TargetFileMimeType"] = file["content_type"]

    if "sha256" in file:
        log["TargetFileSHA256"] = file["sha256"]

    if "size" in file:
        log["TargetFileSize"] = file["size"]

    if "hostname" in server:
        log["DvcHostname"] = server["hostname"]
    elif hasattr(request, "environ") and "SERVER_NAME" in request.environ:
        log["DvcHostname"] = request.environ["SERVER_NAME"]

    if "ip_address" in client:
        log["SrcIpAddr"] = client["ip_address"]
    elif hasattr(request, "environ") and "REMOTE_ADDR" in request.environ:
        log["SrcIpAddr"] = request.environ.get("REMOTE_ADDR")

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


log_file_activity.Event = FileActivityEvent
log_file_activity.Result = Result
log_file_activity.Severity = Severity
