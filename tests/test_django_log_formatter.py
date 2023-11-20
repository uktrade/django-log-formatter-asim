import json
import logging
import os
from io import StringIO

import pytest
from django.conf import settings
from django.test import RequestFactory
from freezegun import freeze_time

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

    def unset_username(self):
        self.username = None

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"


class TestASIMFormatter:
    @freeze_time("2023-10-17 07:15:30")
    def test_system_formatter_logs_correct_fields(self):
        logger_name = "django"
        logger, log_buffer = self._create_logger(logger_name)

        logger.debug("Test log message")

        output = self._get_json_log_entry(log_buffer)
        self._assert_base_fields(
            expected_log_time="2023-10-17T07:15:30",
            logger_name=logger_name,
            output=output,
        )

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

        output = self._get_json_log_entry(log_buffer)
        assert output["EventSeverity"] == expected_severity
        assert output["EventOriginalSeverity"] == str(log_method_name).upper()

    @freeze_time("2023-10-17 07:15:30")
    def test_request_formatter_logs_correct_fields(self):
        logger_name = "django.request"
        logger, log_buffer = self._create_logger(logger_name)
        overrides = {
            "remote_address": "10.9.8.7",
            "server_port": "567",
            "user_agent": "Test user agent",
        }

        self._create_request_log(
            logger,
            overrides,
        )

        output = self._get_json_log_entry(log_buffer)
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
        assert output["HttpUserAgent"] == "Test user agent"

    @pytest.mark.parametrize(
        "log_sensitive_user_data",
        [
            ("UNSET"),
            (False),
        ],
    )
    def test_does_not_log_username_when_log_sensitive_user_data_is_off(
        self, log_sensitive_user_data
    ):
        if log_sensitive_user_data != "UNSET":
            settings.DLFA_LOG_SENSITIVE_USER_DATA = log_sensitive_user_data
        logger, log_buffer = self._create_logger("django.request")
        overrides = {
            "user": self._create_user(),
        }

        self._create_request_log(
            logger,
            overrides,
        )

        output = self._get_json_log_entry(log_buffer)
        assert output["SrcUserId"] == "test_user_id"
        assert output["SrcUsername"] == "REDACTED"

    def test_logs_username_when_log_sensitive_user_data_is_on(self):
        settings.DLFA_LOG_SENSITIVE_USER_DATA = True
        logger, log_buffer = self._create_logger("django.request")
        overrides = {
            "user": self._create_user(),
        }

        self._create_request_log(
            logger,
            overrides,
        )

        output = self._get_json_log_entry(log_buffer)
        assert output["SrcUsername"] == "test_username"

    def test_logs_email_as_username_when_username_is_not_set(self):
        settings.DLFA_LOG_SENSITIVE_USER_DATA = True
        logger, log_buffer = self._create_logger("django.request")
        overrides = {
            "user": self._create_user(),
        }
        overrides["user"].unset_username()

        self._create_request_log(
            logger,
            overrides,
        )

        output = self._get_json_log_entry(log_buffer)
        assert output["SrcUsername"] == "test_email@test.com"

    def _assert_base_fields(self, expected_log_time, logger_name, output):
        # Event fields...
        assert output["EventMessage"] == "Test log message"
        assert output["EventCount"] == 1
        assert output["EventStartTime"] == expected_log_time
        assert output["EventEndTime"] == expected_log_time
        assert output["EventType"] == "ProcessCreated"
        assert output["EventSeverity"] == "Informational"
        assert output["EventOriginalSeverity"] == "DEBUG"
        assert output["EventSchemaVersion"] == "0.1.4"
        assert output["EventSchema"] == "ProcessEvent"

        # Acting Application fields...
        assert output["ActingAppType"] == "Django"

        # Additional fields...
        # We are not checking the whole object here as it would be brittle,
        # and we can trust Python to get it right
        assert f'"name": "{logger_name}", "msg": "Test log message",' in output["AdditionalFields"]

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

        if overrides.get("user"):
            request.__setattr__("user", overrides.get("user"))

        return request

    def _create_user(self):
        return User(
            email="test_email@test.com",
            user_id="test_user_id",
            first_name="Test first name",
            last_name="Test last name",
            username="test_username",
        )

    def _create_request_log(self, logger, overrides={}):
        request = self._create_request(overrides=overrides)
        logger.debug(
            msg="Test log message",
            extra={
                "request": request,
            },
        )

    def _get_json_log_entry(self, log_buffer):
        json_output = log_buffer.getvalue()
        return json.loads(json_output)
