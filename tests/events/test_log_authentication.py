import datetime
import os
from collections import namedtuple

import pytest
from common_events import CommonEvents
from freezegun import freeze_time

from django_log_formatter_asim.events import log_authentication


class TestLogAuthentication(CommonEvents):
    def test_authentication_specifying_all_fields(self, wsgi_request, capsys):
        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logon,
            result=log_authentication.Result.Failure,
            login_method=log_authentication.LoginMethod.UsernamePassword,
            user={
                "username": "Billy-the-fish",
                "role": "Administrator",
                "sessionId": "abc123",
            },
            server={
                "domain_name": "web.trade.gov.uk",
                "ip_address": "127.0.0.1",
                "service_name": "berry-auctions-frontend",
            },
            client={"ip_address": "192.168.1.100", "requested_url": "https://trade.gov.uk/fish"},
            severity=log_authentication.Severity.Low,
            time_generated=datetime.datetime(2025, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc),
            result_details="Biometric and SmartCard authentication",
            message="Billy tried real hard to get in, but his fishy features werent recognised",
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        # ASIM CommonFields
        assert structured_log_entry["EventSchema"] == "Authentication"
        assert structured_log_entry["EventSchemaVersion"] == "0.1.4"
        assert structured_log_entry["EventType"] == "Logon"
        assert structured_log_entry["EventResult"] == "Failure"
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
        assert (
            structured_log_entry["EventResultDetails"] == "Biometric and SmartCard authentication"
        )

        # ASIM Authentication Specific Fields
        assert structured_log_entry["LogonMethod"] == "Username & Password"
        assert structured_log_entry["TargetUsername"] == "Billy-the-fish"
        assert structured_log_entry["TargetSessionId"] == "abc123"
        assert structured_log_entry["TargetUserType"] == "Administrator"

    @pytest.mark.parametrize(
        "event, event_result, expected_event_code",
        [
            ("Logon", "Success", "001a"),
            ("Logon", "Failure", "001b"),
            ("Logoff", "Success", "001c"),
            ("Logoff", "Failure", "001d"),
            ("Logon", "Partial", "001"),
            ("Logoff", "Partial", "001"),
            ("Invalid", "Invalid", "001"),
        ],
    )
    def test_authentication_event_codes(
        self, wsgi_request, capsys, event, event_result, expected_event_code
    ):
        log_authentication(
            wsgi_request,
            event=event,
            result=event_result,
            login_method=log_authentication.LoginMethod.UsernamePassword,
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["EventOriginalType"] == expected_event_code

    @freeze_time("2025-07-02 08:15:20")
    def test_authentication_populates_logs_from_current_time_and_request_varaible(
        self, wsgi_request, capsys
    ):
        os.environ["COPILOT_APPLICATION_NAME"] = "export-analytics"
        os.environ["COPILOT_SERVICE_NAME"] = "frontend"
        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UsernamePassword,
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
        assert structured_log_entry["TargetSessionId"] == "def456"

    @pytest.mark.parametrize(
        "event_result, expected_event_severity",
        [
            ("Success", "Informational"),
            ("Failure", "Medium"),
            ("Partial", "Medium"),
            ("NA", "Medium"),
        ],
    )
    def test_authentication_sets_event_severity_based_on_result(
        self, wsgi_request, capsys, event_result, expected_event_severity
    ):
        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=event_result,
            login_method=log_authentication.LoginMethod.UsernamePassword,
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["EventSeverity"] == expected_event_severity

    def test_authentication_does_not_populate_fields_which_are_not_provided(
        self, wsgi_request, capsys
    ):
        wsgi_request.user = namedtuple("User", ["username"])(None)
        wsgi_request.session = namedtuple("Session", ["session_key"])(None)

        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UsernamePassword,
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert "TargetUserType" not in structured_log_entry
        assert "TargetSessionId" not in structured_log_entry
        assert "TargetUsername" not in structured_log_entry
        assert "DvcIpAddr" not in structured_log_entry
        assert "TargetAppName" not in structured_log_entry
        assert "EventMessage" not in structured_log_entry
        assert "EventResultDetails" not in structured_log_entry

    def test_authentication_populates_fields_which_are_provided_as_none(self, wsgi_request, capsys):
        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UsernamePassword,
            user={"role": None, "sessionId": None, "username": None},
            server={"domain_name": None, "service_name": None},
            client={"ip_address": None},
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["TargetUserType"] is None
        assert structured_log_entry["TargetSessionId"] is None
        assert structured_log_entry["HttpHost"] is None
        assert structured_log_entry["TargetAppName"] is None
        assert structured_log_entry["TargetUsername"] is None
        assert structured_log_entry["SrcIpAddr"] is None

    def generate_event(self, wsgi_request):
        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UsernamePassword,
        )
