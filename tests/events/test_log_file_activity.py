import datetime
import os
from collections import namedtuple

import pytest
from common_events import CommonEvents
from freezegun import freeze_time

from django_log_formatter_asim.events import log_file_activity


class TestLogFileActivity(CommonEvents):
    def test_specifying_all_fields(self, wsgi_request, capsys):
        log_file_activity(
            wsgi_request,
            event=log_file_activity.Event.FileCopied,
            result=log_file_activity.Result.Success,
            result_details="Really top notch CopyObject",
            severity=log_file_activity.Severity.Low,
            time_generated=datetime.datetime(2025, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc),
            message="Billy tried real hard to get in, but his fishy features werent recognised",
            user={
                "username": "Billy-the-fish",
            },
            server={
                "domain_name": "web.trade.gov.uk",
                "ip_address": "127.0.0.1",
                "service_name": "berry-auctions-frontend",
            },
            client={"ip_address": "192.168.1.100", "requested_url": "https://trade.gov.uk/fish"},
            file={
                "path": "s3-1234.bucket.amazon.com/dir1/file.txt",
                "name": "file.txt",
                "extension": "txt",
                "content_type": "plain/text",
                "sha256": "e81bb824c4a09a811af17deae22f22dd2e1ec8cbb00b22629d2899f7c68da274",
                "size": 111,
            },
            source_file={
                "path": "s3-abcd.bucket.amazon.com/dir2/file.exe",
                "name": "file.exe",
                "extenson": "exe",
                "content_type": "application/vnd.microsoft.portable-executable",
                "sha256": "e81bb824c4a09a811af17deae22f22dd2e1ec8cbb00b22629d2899f7c68da274",
                "size": 111,
            },
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        # ASIM CommonFields
        assert structured_log_entry["EventSchema"] == "FileEvent"
        assert structured_log_entry["EventSchemaVersion"] == "0.2.1"
        assert structured_log_entry["EventType"] == "FileCopied"
        assert structured_log_entry["EventResult"] == "Success"
        assert structured_log_entry["EventStartTime"] == "2025-01-02T03:04:05+00:00"
        assert structured_log_entry["HttpHost"] == "web.trade.gov.uk"
        assert structured_log_entry["DvcIpAddr"] == "127.0.0.1"
        assert structured_log_entry["EventSeverity"] == "Low"
        assert structured_log_entry["TargetAppName"] == "berry-auctions-frontend"
        assert structured_log_entry["TargetUrl"] == "https://trade.gov.uk/fish"
        assert (
            structured_log_entry["EventMessage"]
            == "Billy tried real hard to get in, but his fishy features werent recognised"
        )
        assert structured_log_entry["SrcIpAddr"] == "192.168.1.100"
        assert structured_log_entry["EventResultDetails"] == "Really top notch CopyObject"

        # ASIM FileEvent Specific Fields
        assert structured_log_entry["TargetUsername"] == "Billy-the-fish"
        assert structured_log_entry["TargetFilePath"] == "s3-1234.bucket.amazon.com/dir1/file.txt"
        assert structured_log_entry["TargetFileName"] == "file.txt"
        assert structured_log_entry["TargetFileExtension"] == "txt"
        assert structured_log_entry["TargetFileMimeType"] == "plain/text"
        assert (
            structured_log_entry["TargetFileSHA256"]
            == "e81bb824c4a09a811af17deae22f22dd2e1ec8cbb00b22629d2899f7c68da274"
        )
        assert structured_log_entry["TargetFileSize"] == 111

        assert structured_log_entry["SrcFilePath"] == "s3-abcd.bucket.amazon.com/dir2/file.exe"
        assert structured_log_entry["SrcFileName"] == "file.exe"
        assert structured_log_entry["SrcFileExtension"] == "exe"
        assert (
            structured_log_entry["SrcFileMimeType"]
            == "application/vnd.microsoft.portable-executable"
        )
        assert (
            structured_log_entry["SrcFileSHA256"]
            == "e81bb824c4a09a811af17deae22f22dd2e1ec8cbb00b22629d2899f7c68da274"
        )
        assert structured_log_entry["SrcFileSize"] == 111

    @freeze_time("2025-07-02 08:15:20")
    def test_populates_logs_from_current_time_and_request_varaible(self, wsgi_request, capsys):
        os.environ["COPILOT_APPLICATION_NAME"] = "export-analytics"
        os.environ["COPILOT_SERVICE_NAME"] = "frontend"
        log_file_activity(
            wsgi_request,
            event=log_file_activity.Event.FileCreated,
            result=log_file_activity.Result.Success,
            file={
                "path": "s3-1234.bucket.amazon.com/dir1/file.txt",
                "name": "file.txt",
                "extension": "txt",
                "content_type": "plain/text",
                "sha256": "e81bb824c4a09a811af17deae22f22dd2e1ec8cbb00b22629d2899f7c68da274",
                "size": 111,
            },
        )
        del os.environ["COPILOT_APPLICATION_NAME"]
        del os.environ["COPILOT_SERVICE_NAME"]

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["EventStartTime"] == "2025-07-02T08:15:20+00:00"
        assert structured_log_entry["HttpHost"] == "WebServer.local"
        assert structured_log_entry["SrcIpAddr"] == "192.168.1.101"
        assert structured_log_entry["TargetAppName"] == "export-analytics-frontend"
        assert structured_log_entry["TargetUrl"] == "https://WebServer.local/steel"
        assert structured_log_entry["TargetUsername"] == "Adrian"

    @pytest.mark.parametrize(
        "event_result, expected_event_severity",
        [
            ("Success", "Informational"),
            ("Failure", "Medium"),
            ("Partial", "Medium"),
            ("NA", "Medium"),
        ],
    )
    def test_sets_event_severity_based_on_result(
        self, wsgi_request, capsys, event_result, expected_event_severity
    ):
        log_file_activity(
            wsgi_request,
            event=log_file_activity.Event.FileCreated,
            result=event_result,
            file={
                "path": "s3-1234.bucket.amazon.com/dir1/file.txt",
            },
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["EventSeverity"] == expected_event_severity

    @pytest.mark.parametrize(
        "filepath, expected_filename, expected_extension",
        [
            ("s3-1234.bucket.amazon.com/dir1/file.txt", "file.txt", "txt"),
            ("C:/Windows/System32/KERNEL32.DLL", "KERNEL32.DLL", "DLL"),
            ("ftp://127.0.0.1/Documents/secrets.xml", "secrets.xml", "xml"),
            (".env", ".env", None),
            ("/etc/passwd", "passwd", None),
            ("/opt/pooma.tar.bz2", "pooma.tar.bz2", "tar.bz2"),
        ],
    )
    def test_calculates_filename_and_extension_when_not_provided(
        self, wsgi_request, capsys, filepath, expected_filename, expected_extension
    ):
        log_file_activity(
            wsgi_request,
            event=log_file_activity.Event.FileCreated,
            result=log_file_activity.Result.Success,
            file={
                "path": filepath,
            },
            source_file={
                "path": filepath,
            },
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["TargetFileName"] == expected_filename
        assert structured_log_entry["SrcFileName"] == expected_filename
        if expected_extension is None:
            assert "TargetFileExtension" not in structured_log_entry
            assert "SrcFileExtension" not in structured_log_entry
        else:
            assert structured_log_entry["TargetFileExtension"] == expected_extension
            assert structured_log_entry["SrcFileExtension"] == expected_extension

    def test_does_not_populate_fields_which_are_not_provided(self, wsgi_request, capsys):
        wsgi_request.user = namedtuple("User", ["username"])(None)
        wsgi_request.session = namedtuple("Session", ["session_key"])(None)

        log_file_activity(
            wsgi_request,
            event=log_file_activity.Event.FileCreated,
            result=log_file_activity.Result.Success,
            file={
                "path": "s3-1234.bucket.amazon.com/dir1/file.txt",
            },
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert "TargetUsername" not in structured_log_entry
        assert "DvcIpAddr" not in structured_log_entry
        assert "TargetAppName" not in structured_log_entry
        assert "EventMessage" not in structured_log_entry
        assert "EventResultDetails" not in structured_log_entry

        assert "TargetFileMimeType" not in structured_log_entry
        assert "TargetFileSHA256" not in structured_log_entry
        assert "TargetFileSize" not in structured_log_entry

        assert "SrcFilePath" not in structured_log_entry
        assert "SrcFileName" not in structured_log_entry
        assert "SrcFileExtension" not in structured_log_entry
        assert "SrcFileMimeType" not in structured_log_entry
        assert "SrcFileSHA256" not in structured_log_entry
        assert "SrcFileSize" not in structured_log_entry

    def test_populates_fields_which_are_provided_as_none(self, wsgi_request, capsys):
        log_file_activity(
            wsgi_request,
            event=log_file_activity.Event.FileCreated,
            result=log_file_activity.Result.Success,
            file={
                "path": "s3-1234.bucket.amazon.com/dir1/file.txt",
            },
            user={"username": None},
            server={"domain_name": None, "service_name": None},
            client={"ip_address": None},
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["TargetUsername"] is None
        assert structured_log_entry["HttpHost"] is None
        assert structured_log_entry["SrcIpAddr"] is None
        assert structured_log_entry["TargetAppName"] is None

    def generate_event(self, wsgi_request):
        log_file_activity(
            wsgi_request,
            event=log_file_activity.Event.FileCreated,
            result=log_file_activity.Result.Success,
            file={
                "path": "s3-1234.bucket.amazon.com/dir1/file.txt",
            },
        )
