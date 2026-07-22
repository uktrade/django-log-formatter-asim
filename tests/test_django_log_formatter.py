import json
import logging
import os
from importlib.metadata import distribution
from unittest.mock import MagicMock
from unittest.mock import patch

import ddtrace
import pytest
from django.conf import settings
from django.test import AsyncRequestFactory
from django.test import RequestFactory
from freezegun import freeze_time

from django_log_formatter_asim import ASIMFormatter
from django_log_formatter_asim import ASIMRequestFormatter

TEST_USERNAME = "test_username"
TEST_EMAIL = "test_email@test.com"
TEST_LAST_NAME = "Test last name"
TEST_FIRST_NAME = "Test first name"
TEST_PASSWORD = "mypassword123"


class SpyLogHandler(logging.Handler):
    """A handler class which stores LogRecord entries in a list."""

    def __init__(self, records_list):
        """Initiate the handler :param records_list: a list to store the
        LogRecords entries."""
        self.records_list = records_list
        super().__init__()

    def emit(self, record):
        self.records_list.append(record)


@pytest.mark.django_db
class TestASIMFormatter:
    @pytest.fixture(autouse=True)
    def caplog_asim_formatter(self, caplog):
        caplog.handler.setFormatter(ASIMFormatter())

    @pytest.fixture(autouse=True)
    def reset_settings(self, caplog):
        if getattr(settings, "DLFA_TRACE_HEADERS", False):
            del settings.DLFA_TRACE_HEADERS
        if getattr(settings, "DLFA_INCLUDE_RAW_LOG", False):
            del settings.DLFA_INCLUDE_RAW_LOG

    @pytest.mark.parametrize(
        "logger_name",
        [
            ("root"),
            ("django"),
        ],
    )
    @freeze_time("2023-10-17 07:15:30")
    def test_system_formatter_logs_correct_fields(self, logger_name, caplog):
        message_content = "testing 123"
        logging.getLogger(logger_name).debug("Test log message: %s", message_content)

        output = self._get_json_log_entry(caplog)
        self._assert_base_fields(
            expected_log_time="2023-10-17T07:15:30+00:00",
            logger_name=logger_name,
            output=output,
        )

        # Additional fields...
        assert output["AdditionalFields"]["TraceHeaders"] == {}

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    @freeze_time("2023-10-17 07:15:30")
    def test_request_formatter_logs_correct_fields(self, request_factory, caplog):
        logger_name = "django.request"
        overrides = {"remote_address": "10.9.8.7", "server_port": "567"}

        self._create_request_log_record(logging.getLogger(logger_name), overrides, request_factory)

        output = self._get_json_log_entry(caplog)
        self._assert_base_fields(
            expected_log_time="2023-10-17T07:15:30+00:00",
            logger_name=logger_name,
            output=output,
        )
        # Source fields...
        assert output["SrcIpAddr"] == overrides["remote_address"]
        assert output["IpAddr"] == overrides["remote_address"]
        assert output["SrcPortNumber"] == overrides["server_port"]

        # Acting Application fields...
        assert output["ActingAppType"] == "Django"

        # Additional fields...
        assert output["AdditionalFields"]["TraceHeaders"] == {
            "X-Amzn-Trace-Id": "X-Amzn-Trace-Id-Value"
        }

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

    expected_user_agent = "Test request.user_agent"

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    def test_request_formatter_sets_http_user_agent(self, request_factory, caplog):
        expected_user_agent = "Test request.headers.user_agent"
        overrides = {
            "user_agent": expected_user_agent,
        }

        self._create_request_log_record(
            logging.getLogger("django.request"), overrides, request_factory
        )

        output = self._get_json_log_entry(caplog)
        assert output["HttpUserAgent"] == expected_user_agent

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    @pytest.mark.parametrize(
        "trace_header_setting, expected_trace_headers",
        [
            (None, {"X-Amzn-Trace-Id": "X-Amzn-Trace-Id-Value"}),
            (
                ("X-B3-TraceId", "X-B3-SpanId"),
                {"X-B3-TraceId": "X-B3-TraceId-Value", "X-B3-SpanId": "X-B3-SpanId-Value"},
            ),
        ],
    )
    @freeze_time("2023-10-17 07:15:30")
    def test_request_formatter_logs_trace_header_with_fallback_to_default(
        self, request_factory, trace_header_setting, expected_trace_headers, caplog
    ):
        if trace_header_setting:
            settings.DLFA_TRACE_HEADERS = trace_header_setting
        overrides = {"trace_headers": expected_trace_headers}

        self._create_request_log_record(
            logging.getLogger("django.request"), overrides, request_factory
        )

        output = self._get_json_log_entry(caplog)
        assert "TraceHeaders" in output["AdditionalFields"]
        actual_trace_headers = output["AdditionalFields"]["TraceHeaders"]
        assert len(actual_trace_headers) == len(expected_trace_headers)
        for expected_header, expected_value in expected_trace_headers.items():
            assert actual_trace_headers[expected_header] == expected_value

    def test_does_not_includes_raw_log_by_default(self, caplog):
        logging.getLogger("django").debug("Test log message")

        output = self._get_json_log_entry(caplog)

        # We are not checking the whole AdditionalFields.RawLog object here as it would be brittle,
        # and we can trust Python to get it right,
        # so we just test that the start exists and looks realistic...
        assert "RawLog" not in output["AdditionalFields"]

    def test_log_includes_raw_log_with_dlfa_include_raw_log_true(self, caplog):
        settings.DLFA_INCLUDE_RAW_LOG = True
        logger_name = "django"
        expected_message = "Test log message"
        logging.getLogger(logger_name).debug(expected_message)

        output = self._get_json_log_entry(caplog)

        # We are not checking the whole AdditionalFields.RawLog object here as it would be brittle,
        # and we can trust Python to get it right,
        # so we just test that the start exists and looks realistic...
        assert (
            f'"name": "{logger_name}", "msg": "{expected_message}",'
            in output["AdditionalFields"]["RawLog"]
        )

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    @pytest.mark.parametrize(
        "log_sensitive_user_data",
        [
            ("UNSET"),
            (False),
        ],
    )
    def test_does_not_log_personally_identifiable_information_when_log_sensitive_user_data_is_off(
        self, request_factory, log_sensitive_user_data, caplog
    ):
        settings.DLFA_INCLUDE_RAW_LOG = True
        if log_sensitive_user_data != "UNSET":
            settings.DLFA_LOG_PERSONALLY_IDENTIFIABLE_INFORMATION = log_sensitive_user_data
        overrides = {
            "user": self._create_user(),
        }

        self._create_request_log_record(
            logging.getLogger("django.request"), overrides, request_factory
        )

        output = self._get_json_log_entry(caplog)
        raw_log = output["AdditionalFields"]["RawLog"]

        assert output["SrcUserId"] > 0
        assert TEST_PASSWORD not in raw_log
        assert "{{PASSWORD}}" in raw_log

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    def test_logs_log_personally_identifiable_information_when_log_sensitive_user_data_is_on(
        self, request_factory, caplog
    ):
        settings.DLFA_INCLUDE_RAW_LOG = True
        settings.DLFA_LOG_PERSONALLY_IDENTIFIABLE_INFORMATION = True
        overrides = {
            "user": self._create_user(),
        }

        self._create_request_log_record(
            logging.getLogger("django.request"), overrides, request_factory
        )

        output = self._get_json_log_entry(caplog)
        assert output["SrcUsername"] == TEST_USERNAME
        raw_log = output["AdditionalFields"]["RawLog"]
        assert TEST_USERNAME in raw_log
        assert TEST_EMAIL in raw_log
        assert TEST_FIRST_NAME in raw_log
        assert TEST_LAST_NAME in raw_log

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    @patch("ddtrace.trace.tracer.current_span")
    def test_logs_log_datadog_required_values_when_env_vars_set(
        self, mock_ddtrace_span, request_factory, caplog
    ):
        os.environ["DD_ENV"] = "test"
        os.environ["DD_SERVICE"] = "django-service"
        os.environ["DD_VERSION"] = "1.0.0"
        ddtrace.config = ddtrace.internal.settings._config.Config()

        mock_ddtrace_span_response = MagicMock()
        mock_ddtrace_span_response.trace_id = 5735492756521486600
        mock_ddtrace_span_response.span_id = 12448338029536640280
        mock_ddtrace_span.return_value = mock_ddtrace_span_response

        self._create_request_log_record(
            logging.getLogger("django.request"), overrides={}, request_factory=request_factory
        )

        output = self._get_json_log_entry(caplog)
        assert output["service"] == "django-service"
        assert output["env"] == "test"
        assert output["version"] == "1.0.0"
        assert output["dd.trace_id"] == "5735492756521486600"
        assert output["dd.span_id"] == "12448338029536640280"
        assert output["container_id"] == "709d1c10779d47b2a84db9eef2ebd041-0265927825"

        os.environ.pop("DD_ENV")
        os.environ.pop("DD_SERVICE")
        os.environ.pop("DD_VERSION")
        ddtrace.config = ddtrace.internal.settings._config.Config()

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    @patch("ddtrace.trace.tracer.current_span")
    def test_logs_log_datadog_required_values_when_env_vars_not_set(
        self, mock_ddtrace_span, request_factory, caplog
    ):
        mock_ddtrace_span_response = MagicMock()
        mock_ddtrace_span_response.trace_id = 5735492756521486600
        mock_ddtrace_span_response.span_id = 12448338029536640280
        mock_ddtrace_span.return_value = mock_ddtrace_span_response

        self._create_request_log_record(
            logging.getLogger("django.request"), overrides={}, request_factory=request_factory
        )

        output = self._get_json_log_entry(caplog)
        assert output["service"] == ""
        assert output["env"] == ""
        assert output["version"] == ""
        assert output["dd.trace_id"] == "5735492756521486600"
        assert output["dd.span_id"] == "12448338029536640280"
        assert output["container_id"] == "709d1c10779d47b2a84db9eef2ebd041-0265927825"

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    def test_logs_anonymous_user_when_no_user_logged_in(self, request_factory, caplog):
        from django.contrib.auth.models import AnonymousUser

        overrides = {
            "user": AnonymousUser(),
        }

        self._create_request_log_record(
            logging.getLogger("django.request"), overrides, request_factory
        )

        output = self._get_json_log_entry(caplog)
        assert output["SrcUserId"] is None
        assert output["SrcUsername"] == "AnonymousUser"

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    def test_serialize_user(self, request_factory):
        request_log = self._create_request_log_record(
            logging.getLogger("django.request"), overrides={}, request_factory=request_factory
        )
        user = self._create_user()
        user.random_field_name = "blah"

        serialized_user = ASIMRequestFormatter(request_log)._serialize_user(user)

        assert serialized_user.get("username") == user.username
        assert serialized_user.get("email") == user.email
        assert serialized_user.get("first_name") == user.first_name
        assert serialized_user.get("last_name") == user.last_name
        assert serialized_user.get("password") == user.password
        assert serialized_user.get("date_joined") == user.date_joined.isoformat()
        assert serialized_user.get("is_active") == user.is_active
        assert serialized_user.get("is_staff") == user.is_staff
        assert serialized_user.get("is_superuser") == user.is_superuser
        assert "random_field_name" not in serialized_user.keys()

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    def test_serialize_request(self, request_factory):
        request_log = self._create_request_log_record(
            logging.getLogger("django.request"), overrides={}, request_factory=request_factory
        )
        request = request_log.request
        request.user = self._create_user()
        request.random_field_name = "blah"

        serialized_request = ASIMRequestFormatter(request_log)._serialize_request(request)

        assert serialized_request.get("method") == request.method
        assert serialized_request.get("path") == request.path
        assert serialized_request.get("GET") == dict(request.GET)
        assert serialized_request.get("POST") == dict(request.POST)
        assert serialized_request.get("headers") == dict(request.headers)
        assert serialized_request.get("user") == ASIMRequestFormatter(request_log)._serialize_user(
            request.user
        )

    @pytest.mark.parametrize(
        "request_factory",
        [
            RequestFactory,
            AsyncRequestFactory,
        ],
    )
    def test_request_formatter_get_log_dict_with_raw(self, request_factory):
        request_log = self._create_request_log_record(
            logging.getLogger("django.request"), overrides={}, request_factory=request_factory
        )
        request_log.request.user = self._create_user()

        formatter = ASIMRequestFormatter(request_log)
        log_dict_with_raw = formatter.get_log_dict_with_raw({"AdditionalFields": {}})
        serialized_request = formatter._serialize_request(request_log.request)
        record_dict = vars(request_log).copy()
        record_dict["request"] = serialized_request

        assert log_dict_with_raw["AdditionalFields"]["RawLog"] == json.dumps(record_dict)

    def test_root_formatter_get_log_dict_with_raw(self):
        pass

    def _assert_base_fields(self, expected_log_time, logger_name, output):
        # Event fields...
        assert output["EventMessage"] == "Test log message: testing 123"
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
        assert (
            output["AdditionalFields"]["DjangoLogFormatterAsimVersion"]
            == distribution("django-log-formatter-asim").version
        )

    def _create_request(self, overrides=None, request_factory=RequestFactory):
        if overrides is None:
            overrides = {}
        headers = {"X-Amzn-Trace-Id": "X-Amzn-Trace-Id-Value"}

        if overrides.get("user_agent"):
            headers["User-Agent"] = overrides["user_agent"]
        if overrides.get("trace_headers"):
            headers.update(overrides["trace_headers"])

        request = request_factory().get(path="/", data={}, headers=headers)

        if overrides.get("server_port"):
            request.META["SERVER_PORT"] = overrides["server_port"]
        if overrides.get("remote_address"):
            request.META["REMOTE_ADDR"] = overrides["remote_address"]
        if overrides.get("user"):
            request.user = overrides["user"]

        return request

    def _create_user(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User.objects.create_user(
            username=TEST_USERNAME,
            email=TEST_EMAIL,
            password="test-password",
            first_name=TEST_FIRST_NAME,
            last_name=TEST_LAST_NAME,
        )
        return user

    def _create_request_log_record(self, logger, overrides={}, request_factory=RequestFactory):
        request = self._create_request(overrides=overrides, request_factory=request_factory)
        logger.addHandler(SpyLogHandler(records_list=[]))
        message_content = "testing 123"
        logger.debug(
            "Test log message: %s",
            message_content,
            extra={
                "request": request,
            },
        )

        return logger.handlers[-1].records_list[-1]

    def _get_json_log_entry(self, caplog):
        return json.loads(caplog.text)
