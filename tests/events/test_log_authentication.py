import datetime
import json
from collections import namedtuple

import pytest
from freezegun import freeze_time

from django_log_formatter_asim.events import log_authentication


class TestLogAuthentication:
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
            server={"hostname": "BigServer", "ip_address": "127.0.0.1"},
            client={"ip_address": "192.168.1.100"},
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
        assert structured_log_entry["EventCreated"] == "2025-01-02T03:04:05+00:00"
        assert structured_log_entry["DvcHostname"] == "BigServer"
        assert structured_log_entry["DvcIpAddr"] == "127.0.0.1"
        assert structured_log_entry["EventSeverity"] == "Low"
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
        assert structured_log_entry["ActorUsername"] == "Billy-the-fish"
        assert structured_log_entry["ActorSessionId"] == "abc123"
        assert structured_log_entry["ActorUserType"] == "Administrator"

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
        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UsernamePassword,
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["EventCreated"] == "2025-07-02T08:15:20+00:00"
        assert structured_log_entry["DvcHostname"] == "WebServer.local"
        assert structured_log_entry["SrcIpAddr"] == "192.168.1.101"
        assert structured_log_entry["ActorUsername"] == "Adrian"
        assert structured_log_entry["ActorSessionId"] == "def456"

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

    def test_authentication_does_not_populate_fields_which_are_not_provided(self, capsys):
        wsgi_request = namedtuple("Request", ["environ", "user", "session"])(
            {"REMOTE_ADDR": "192.168.1.101", "SERVER_NAME": "WebServer.local"},
            namedtuple("User", ["username"])(None),
            namedtuple("Session", ["session_key"])(None),
        )

        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UsernamePassword,
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert "ActorUserType" not in structured_log_entry
        assert "ActorSessionId" not in structured_log_entry
        assert "ActorUsername" not in structured_log_entry
        assert "DvcIpAddr" not in structured_log_entry
        assert "EventMessage" not in structured_log_entry
        assert "EventResultDetails" not in structured_log_entry

    def test_authentication_does_not_populate_request_environ_fields_when_environ_is_not_provided(
        self, capsys
    ):
        wsgi_request = namedtuple("Request", ["user", "session"])(
            namedtuple("User", ["username"])(None),
            namedtuple("Session", ["session_key"])(None),
        )

        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UsernamePassword,
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert "DvcHostname" not in structured_log_entry
        assert "SrcIpAddr" not in structured_log_entry

    def test_authentication_populates_fields_which_are_provided_as_none(self, wsgi_request, capsys):
        log_authentication(
            wsgi_request,
            event=log_authentication.Event.Logoff,
            result=log_authentication.Result.Success,
            login_method=log_authentication.LoginMethod.UsernamePassword,
            user={"role": None, "sessionId": None, "username": None},
            server={"hostname": None},
            client={"ip_address": None},
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["ActorUserType"] is None
        assert structured_log_entry["ActorSessionId"] is None
        assert structured_log_entry["ActorUsername"] is None
        assert structured_log_entry["DvcHostname"] is None
        assert structured_log_entry["SrcIpAddr"] is None

    def _get_structured_log_entry(self, capsys):
        (out, _) = capsys.readouterr()
        self._assert_has_one_new_line_at_end_of_string(out)
        return json.loads(out)

    def _assert_has_one_new_line_at_end_of_string(self, expected):
        assert expected.find("\n") == len(expected) - 1
