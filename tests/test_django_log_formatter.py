import json
import logging

import pytest
from django.conf import settings
from django.test import RequestFactory
from freezegun import freeze_time

from django_log_formatter_asim import ASIMFormatter

TEST_USERNAME = "test_username"
TEST_EMAIL = "test_email@test.com"
TEST_LAST_NAME = "Test last name"
TEST_FIRST_NAME = "Test first name"


@pytest.mark.django_db
class TestASIMFormatter:
    @pytest.fixture(autouse=True)
    def caplog_asim_formatter(self, caplog):
        caplog.handler.setFormatter(ASIMFormatter())

    @pytest.mark.parametrize(
        "logger_name",
        [
            ("root"),
            ("django"),
        ],
    )
    @freeze_time("2023-10-17 07:15:30")
    def test_system_formatter_logs_correct_fields(self, logger_name, caplog):
        logging.getLogger(logger_name).debug("Test log message")

        output = self._get_json_log_entry(caplog)
        self._assert_base_fields(
            expected_log_time="2023-10-17T07:15:30",
            logger_name=logger_name,
            output=output,
        )

    @freeze_time("2023-10-17 07:15:30")
    def test_request_formatter_logs_correct_fields(self, caplog):
        logger_name = "django.request"
        overrides = {"remote_address": "10.9.8.7", "server_port": "567"}

        self._create_request_log(logging.getLogger(logger_name), overrides)

        output = self._get_json_log_entry(caplog)
        self._assert_base_fields(
            expected_log_time="2023-10-17T07:15:30",
            logger_name=logger_name,
            output=output,
        )
        # Source fields...
        assert output["SrcIpAddr"] == overrides["remote_address"]
        assert output["IpAddr"] == overrides["remote_address"]
        assert output["SrcPortNumber"] == overrides["server_port"]

        # Acting Application fields...
        assert output["ActingAppType"] == "Django"

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
    def test_formatter_logs_correct_severity(self, log_method_name, expected_severity, caplog):
        log_dot_level = getattr(logging.getLogger("django"), log_method_name)

        log_dot_level(f"Test {log_method_name} log message")

        output = self._get_json_log_entry(caplog)
        assert output["EventSeverity"] == expected_severity
        assert output["EventOriginalSeverity"] == str(log_method_name).upper()

    @pytest.mark.parametrize(
        "user_agent_fields_to_unset, expected_user_agent",
        [
            ([], "Test request.user_agent"),
            (["user_agent"], "Test request.headers.user_agent"),
            (["user_agent", "headers.user_agent"], "Test request.META.HTTP_USER_AGENT"),
            (["user_agent", "headers.user_agent", "META.HTTP_USER_AGENT"], None),
        ],
    )
    def test_request_formatter_sets_http_user_agent_with_fallbacks(
        self,
        user_agent_fields_to_unset,
        expected_user_agent,
        caplog,
    ):
        overrides = {
            "user_agent": "Test request.user_agent",
            "headers.user_agent": "Test request.headers.user_agent",
            "META.HTTP_USER_AGENT": "Test request.META.HTTP_USER_AGENT",
        }
        for field_to_unset in user_agent_fields_to_unset:
            del overrides[field_to_unset]

        self._create_request_log(logging.getLogger("django.request"), overrides)

        output = self._get_json_log_entry(caplog)
        assert output["HttpUserAgent"] == expected_user_agent

    @pytest.mark.parametrize(
        "trace_header_setting, expected_trace_headers",
        [
            (None, {"X-Amzn-Trace-Id": "X-Amzn-Trace-Id-Value"}),
            (
                "DLFE_ZIPKIN_HEADERS",
                {"X-B3-TraceId": "X-B3-SpanId-Value", "X-B3-SpanId": "X-B3-TraceId-Value"},
            ),
        ],
    )
    @freeze_time("2023-10-17 07:15:30")
    def test_request_formatter_logs_trace_header_with_fallback_to_default(
        self, trace_header_setting, expected_trace_headers, caplog
    ):
        overrides = {
            "extra_headers": expected_trace_headers,
        }

        self._create_request_log(logging.getLogger("django.request"), overrides)

        output = self._get_json_log_entry(caplog)
        assert "TraceHeaders" in output["AdditionalFields"]
        actual_trace_headers = output["AdditionalFields"]["TraceHeaders"]
        assert len(actual_trace_headers) == len(expected_trace_headers)
        for expected_header, expected_value in expected_trace_headers:
            assert actual_trace_headers[expected_header] == expected_value

    @pytest.mark.parametrize(
        "log_sensitive_user_data",
        [
            ("UNSET"),
            (False),
        ],
    )
    def test_does_not_log_personally_identifiable_information_when_log_sensitive_user_data_is_off(
        self, log_sensitive_user_data, caplog
    ):
        if log_sensitive_user_data != "UNSET":
            settings.DLFA_LOG_PERSONALLY_IDENTIFIABLE_INFORMATION = log_sensitive_user_data
        overrides = {
            "user": self._create_user(),
        }

        self._create_request_log(logging.getLogger("django.request"), overrides)

        output = self._get_json_log_entry(caplog)
        assert output["SrcUserId"] > 0
        assert output["SrcUsername"] == "{{USERNAME}}"
        raw_log = output["AdditionalFields"]["RawLog"]
        assert TEST_USERNAME not in raw_log
        assert "{{USERNAME}}" in raw_log
        assert TEST_EMAIL not in raw_log
        assert "{{EMAIL}}" in raw_log
        assert TEST_FIRST_NAME not in raw_log
        assert "{{FIRST_NAME}}" in raw_log
        assert TEST_LAST_NAME not in raw_log
        assert "{{LAST_NAME}}" in raw_log

    def test_logs_log_personally_identifiable_information_when_log_sensitive_user_data_is_on(
        self, caplog
    ):
        settings.DLFA_LOG_PERSONALLY_IDENTIFIABLE_INFORMATION = True
        overrides = {
            "user": self._create_user(),
        }

        self._create_request_log(logging.getLogger("django.request"), overrides)

        output = self._get_json_log_entry(caplog)
        assert output["SrcUsername"] == TEST_USERNAME

    def test_logs_anonymous_user_when_no_user_logged_in(self, caplog):
        from django.contrib.auth.models import AnonymousUser

        overrides = {
            "user": AnonymousUser(),
        }

        self._create_request_log(logging.getLogger("django.request"), overrides)

        output = self._get_json_log_entry(caplog)
        assert output["SrcUserId"] is None
        assert output["SrcUsername"] == "AnonymousUser"

    def _assert_base_fields(self, expected_log_time, logger_name, output):
        # Event fields...
        assert output["EventMessage"] == "Test log message"
        assert output["EventCount"] == 1
        assert output["EventStartTime"] == expected_log_time
        assert output["EventEndTime"] == expected_log_time
        assert output["EventType"] == logger_name
        assert output["EventSeverity"] == "Informational"
        assert output["EventOriginalSeverity"] == "DEBUG"
        assert output["EventSchemaVersion"] == "0.1.4"
        assert output["EventSchema"] == "ProcessEvent"

        # Acting Application fields...
        assert output["ActingAppType"] == "Django"

        # Additional fields...
        # We are not checking the whole AdditionalFields.RawLog object here as it would be brittle,
        # and we can trust Python to get it right,
        # so we just test that the start exists and looks realistic...
        assert (
            f'"name": "{logger_name}", "msg": "Test log message",'
            in output["AdditionalFields"]["RawLog"]
        )

    def _create_request(self, overrides=None):
        if overrides is None:
            overrides = {}
        request = RequestFactory().get(path="/")

        if overrides.get("remote_address"):
            request.environ["REMOTE_ADDR"] = overrides.get("remote_address")
            request.META["REMOTE_ADDR"] = overrides.get("remote_address")

        if overrides.get("server_port"):
            request.environ["SERVER_PORT"] = overrides.get("server_port")

        if overrides.get("user_agent"):
            request.__setattr__("user_agent", overrides.get("user_agent"))

        if overrides.get("headers.user_agent"):
            request.headers.__setattr__("user_agent", overrides.get("headers.user_agent"))

        if overrides.get("extra_headers"):
            request.headers = {**request.headers, **overrides.get("extra_headers")}

        if overrides.get("META.HTTP_USER_AGENT"):
            request.META["HTTP_USER_AGENT"] = overrides.get("META.HTTP_USER_AGENT")

        if overrides.get("user"):
            request.__setattr__("user", overrides.get("user"))

        return request

    def _create_user(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(
            username=TEST_USERNAME, email=TEST_EMAIL, password="test-password"
        )
        return user

    def _create_request_log(self, logger, overrides={}):
        request = self._create_request(overrides=overrides)
        logger.debug(
            msg="Test log message",
            extra={
                "request": request,
            },
        )

    def _get_json_log_entry(self, caplog):
        return json.loads(caplog.text)
