import json
import logging
import os
from io import StringIO

import pytest
from freezegun import freeze_time
from django.conf import settings
from django.test import RequestFactory
from django.test import override_settings

from django_log_formatter_asim import ASIMFormatter

settings.configure(
    DEBUG=True,
    ALLOWED_HOSTS="*",
)


class User:
    def __init__(self, email, user_id, first_name, last_name, username):
        self.email = email
        self.id = user_id
        self.first_name = first_name
        self.last_name = last_name
        self.username = username

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"


@pytest.fixture
def fruit_bowl():
    return [Fruit("apple"), Fruit("banana")]


class TestASIMFormatter:
    # Note that we are explicitly expecting None for properties we are unable to supply

    # def __init__(self):
    #     self.factory = RequestFactory()

    @pytest.mark.parametrize(
        "logger_name",
        [
            ("django"),
            ("django.request"),
        ],
    )
    @freeze_time("2023-10-17 07:15:30")
    def test_formatter_logs_common_event_fields(self, logger_name):
        logger, log_buffer = self._create_logger(logger_name)

        logger.debug("Test")

        json_output = log_buffer.getvalue()
        output = json.loads(json_output)
        expected_log_time = "2023-10-17T07:15:30"
        assert output["EventMessage"] == "Test"
        assert output["EventCount"] == 1
        assert output["EventStartTime"] == expected_log_time
        assert output["EventEndTime"] == expected_log_time
        assert output["EventType"] == "ProcessCreated"
        assert output["EventSubType"] is None
        # We don't have anything for EventResult, but it is mandatory and one of
        # Success, Partial, Failure, NA (Not Applicable).
        assert output["EventResult"] == "NA"
        assert output["EventResultDetails"] is None
        assert output["EventUid"] is None
        assert output["EventOriginalUid"] is None
        assert output["EventOriginalType"] is None
        assert output["EventOriginalSubType"] is None
        assert output["EventOriginalResultDetails"] is None
        assert output["EventSeverity"] == "Informational"
        assert output["EventOriginalSeverity"] == "DEBUG"
        # EventProduct and EventVendor are mandatory, but we don't have anything tha matches the
        # allowed values from
        # https://learn.microsoft.com/en-us/azure/sentinel/normalization-common-fields#vendors-and-products
        # so we will use "Django" for both.
        assert output["EventProduct"] == "Django"
        assert output["EventProductVersion"] is None
        assert output["EventVendor"] == "Django"
        assert output["EventSchemaVersion"] == "0.1.4"
        assert output["EventSchema"] == "ProcessEvent"
        assert output["EventReportUrl"] is None
        assert output["EventOwner"] is None

    @pytest.mark.parametrize(
        "logger_name",
        [
            ("django"),
            ("django.request"),
        ],
    )
    @freeze_time("2023-10-17 07:15:30")
    def test_formatter_logs_common_other_fields(self, logger_name):
        logger, log_buffer = self._create_logger(logger_name)

        logger.debug("Test")

        json_output = log_buffer.getvalue()
        output = json.loads(json_output)
        # We are not checking the whole object here as it would be brittle,
        # and we can trust Python to get it right
        assert f'"name": "{logger_name}", "msg": "Test",' in output["AdditionalFields"]
        if logger_name == "django.request":
            assert f'"name": "{logger_name}", "msg": "Test",' in output["AdditionalFields"]
        assert output["ASimMatchingIpAddr"] is None
        assert output["ASimMatchingHostname"] is None

    def test_system_formatter_logs_process_event_fields(self):
        logger, log_buffer = self._create_logger("django")

        logger.debug("Does not matter")

        json_output = log_buffer.getvalue()
        output = json.loads(json_output)
        assert output["EventType"] == "ProcessCreated"
        assert output["EventSchemaVersion"] == "0.1.4"
        assert output["EventSchema"] == "ProcessEvent"

    @pytest.mark.parametrize(
        "log_method_name, expected_severity",
        [
            ("debug", "Informational"),
            ("info", "Informational"),
            ("warning", "Low"),
            ("error", "Medium"),
            ("critical", "High"),
        ],
    )
    def test_formatter_logs_correct_severity(self, log_method_name, expected_severity):
        logger, log_buffer = self._create_logger("django")
        log_method = getattr(logger, log_method_name)

        log_method("Does not matter")

        json_output = log_buffer.getvalue()
        output = json.loads(json_output)
        assert output["EventSeverity"] == expected_severity
        assert output["EventOriginalSeverity"] == str(log_method_name).upper()

    def test_request_formatter_logs_source_fields(self):
        logger, log_buffer = self._create_logger("django.request")
        expected_remote_address = "10.9.8.7"
        expected_server_port = "567"
        expected_user_agent = "some user agent"
        request = self._create_request(
            overrides={
                "remote_address": expected_remote_address,
                "server_port": expected_server_port,
                "user_agent": expected_user_agent,
            }
        )

        logger.debug(
            msg="Test",
            extra={
                "request": request,
            },
        )

        json_output = log_buffer.getvalue()
        output = json.loads(json_output)

        assert output["Src"] is None
        assert output["SrcIpAddr"] == expected_remote_address
        assert output["IpAddr"] == expected_remote_address  # Todo: Confirm if needed
        assert output["SrcPortNumber"] == expected_server_port
        assert output["SrcHostname"] is None
        assert output["SrcHostname"] is None
        assert output["SrcDomain"] is None
        assert output["SrcDomainType"] is None
        assert output["SrcFQDN"] is None
        assert output["SrcDescription"] == expected_user_agent
        assert output["SrcDvcId"] is None
        assert output["SrcDvcScopeId"] is None
        assert output["SrcDvcScope"] is None
        assert output["SrcDvcIdType"] is None
        assert output["SrcDeviceType"] is None
        assert output["SrcSubscriptionId"] is None
        assert output["SrcGeoCountry"] is None
        assert output["SrcGeoCity"] is None
        assert output["SrcGeoLatitude"] is None
        assert output["SrcGeoLongitude"] is None

    # def test_log_sensitive_user_data_default(self):
    #     output = self._create_request_log(add_user=True)
    #
    #     assert "id" in output["user"]
    #     assert "email" not in output["user"]

    # @override_settings(DLFE_LOG_SENSITIVE_USER_DATA=True)
    # def test_log_sensitive_user_data_on(self):
    #     output = self._create_request_log(add_user=True)
    #
    #     assert output["user"]["id"] == "1"
    #     assert output["user"]["email"] == "test@test.com"
    #     assert output["user"]["full_name"] == "John Test"
    #     assert output["user"]["name"] == "johntest"

    # @override_settings(DLFE_APP_NAME="TestApp")
    # def test_app_name_log_value(self):
    #     output = self._create_request_log()
    #
    #     assert output["event"]["labels"]["application"] == "TestApp"

    # def test_env_unset_log_value(self):
    #     output = self._create_request_log()
    #
    #     assert output["event"]["labels"]["env"] == "Unknown"

    # @patch.dict(os.environ, {"DJANGO_SETTINGS_MODULE": "settings.Test"})
    # def test_env_log_value(self):
    #     output = self._create_request_log()
    #
    #     assert output["event"]["labels"]["env"] == "settings.Test"

    def _create_logger(self, logger_name):
        log_buffer = StringIO()
        asim_handler = logging.StreamHandler(log_buffer)
        asim_handler.setFormatter(ASIMFormatter())

        logger = logging.getLogger(logger_name)
        logger.addHandler(asim_handler)
        logger.setLevel(logging.DEBUG)
        logging.propagate = False

        return logger, log_buffer

    def _create_request(self, add_user=False, overrides=None):
        if overrides is None:
            overrides = {}
        request = RequestFactory().get(path="/")

        if overrides.get("remote_address"):
            request.environ["REMOTE_ADDR"] = overrides.get("remote_address")
            request.META["REMOTE_ADDR"] = overrides.get("remote_address")

        if overrides.get("server_port"):
            request.environ["SERVER_PORT"] = overrides.get("server_port")

        if overrides.get("user_agent"):
            request.headers.__setattr__("USER_AGENT", overrides.get("user_agent"))

        if add_user:
            user = User(
                email="test@test.com",
                user_id=1,
                first_name="John",
                last_name="Test",
                username="johntest",
            )
            setattr(request, "user", user)

        return request
