import datetime
from collections import namedtuple

from common_events import CommonEvents

from django_log_formatter_asim.events import log_account_management


class TestLogAccountManagement(CommonEvents):
    def test_specifying_all_fields(self, wsgi_request, capsys):
        log_account_management(
            wsgi_request,
            event=log_account_management.Event.UserCreated,
            result=log_account_management.Result.Success,
            result_details="Created a new user",
            severity=log_account_management.Severity.Low,
            time_generated=datetime.datetime(2025, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc),
            message="Billy tried real hard to get in, but his fishy features werent recognised",
            account={
                "username": "Roger",
                "group": "Bogart",
                "changed": ("Password", "oldValue", "newValue"),
            },
            user={
                "username": "Billy-the-fish",
            },
            server={
                "domain_name": "web.trade.gov.uk",
                "ip_address": "127.0.0.1",
                "service_name": "berry-auctions-frontend",
            },
            client={"ip_address": "192.168.1.100", "requested_url": "https://trade.gov.uk/fish"},
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        # ASIM CommonFields
        assert structured_log_entry["EventSchema"] == "UserManagement"
        assert structured_log_entry["EventSchemaVersion"] == "0.1.1"
        assert structured_log_entry["EventType"] == "UserCreated"
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
        assert structured_log_entry["EventResultDetails"] == "Created a new user"

        # ASIM FileEvent Specific Fields
        assert structured_log_entry["ActorUsername"] == "Billy-the-fish"

        assert structured_log_entry["TargetUsername"] == "Roger"
        assert structured_log_entry["GroupName"] == "Bogart"
        assert structured_log_entry["UpdatedPropertyName"] == "Password"
        assert structured_log_entry["PreviousPropertyValue"] == "oldValue"
        assert structured_log_entry["NewPropertyValue"] == "newValue"

    def test_does_not_populate_fields_which_are_not_provided(self, wsgi_request, capsys):
        wsgi_request.user = namedtuple("User", ["username"])(None)
        wsgi_request.session = namedtuple("Session", ["session_key"])(None)

        log_account_management(
            wsgi_request,
            event=log_account_management.Event.GroupDeleted,
            result=log_account_management.Result.Success,
            account={},
        )

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert "ActorUsername" not in structured_log_entry
        assert "DvcIpAddr" not in structured_log_entry
        assert "TargetAppName" not in structured_log_entry
        assert "EventMessage" not in structured_log_entry
        assert "EventResultDetails" not in structured_log_entry

        assert "TargetUsername" not in structured_log_entry
        assert "GroupName" not in structured_log_entry
        assert "UpdatedPropertyName" not in structured_log_entry
        assert "PreviousPropertyValue" not in structured_log_entry
        assert "NewPropertyValue" not in structured_log_entry

    def generate_event(self, wsgi_request):
        log_account_management(
            wsgi_request,
            event=log_account_management.Event.UserCreated,
            result=log_account_management.Result.Success,
            account={},
        )
