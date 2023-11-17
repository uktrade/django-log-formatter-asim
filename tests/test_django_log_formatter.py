import json
import logging
import os
from io import StringIO
from unittest import TestCase
from unittest.mock import patch
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


class ASIMFormatterTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def _create_logger(self, logger_name):
        log_buffer = StringIO()
        asim_handler = logging.StreamHandler(log_buffer)
        asim_handler.setFormatter(ASIMFormatter())

        logger = logging.getLogger(logger_name)
        logger.addHandler(asim_handler)
        logger.setLevel(logging.DEBUG)
        logging.propagate = False

        return logger, log_buffer

    def _create_request_log(self, add_user=False):
        request = self.factory.get("/")

        if add_user:
            user = User(
                email="test@test.com",
                user_id=1,
                first_name="John",
                last_name="Test",
                username="johntest",
            )
            setattr(request, "user", user)

        logger, log_buffer = self._create_logger("django.request")
        logger.error(
            msg="Request test",
            extra={
                "request": request,
            },
        )

        json_output = log_buffer.getvalue()

        return json.loads(json_output)

    @freeze_time("2023-10-17 07:15:30")
    def test_system_formatter_logs_common_fields(self):
        logger, log_buffer = self._create_logger("django")

        logger.debug("Test")

        # Note that we are explicitly expecting None for properties we are unable to supply
        json_output = log_buffer.getvalue()
        output = json.loads(json_output)
        expected_log_time = "2023-10-17T07:15:30"
        assert output["EventMessage"] == "Test"
        assert output["EventCount"] == 1
        assert output["EventStartTime"] == expected_log_time
        assert output["EventEndTime"] == expected_log_time
        assert output["EventType"] == "ProcessCreated"
        assert output["EventSubType"] is None
        # We don't have anything for EventResult, but mandatory one of
        # Success, Partial, Failure, NA (Not Applicable).
        assert output["EventResult"] == "NA"
        assert output["EventResultDetails"] is None
        assert output["EventUid"] is None
        assert output["EventOriginalUid"] is None
        assert output["EventOriginalType"] is None
        assert output["EventOriginalSubType"] is None
        assert output["EventOriginalResultDetails"] is None
        # EventSeverity	Recommended	Enumerated	The severity of the event. Valid values are: Informational, Low, Medium, or High.
        # EventOriginalSeverity	Optional	String	The original severity as provided by the reporting device. This value is used to derive EventSeverity.
        # EventProduct	Mandatory	String	The product generating the event. The value should be one of the values listed in Vendors and Products.
        # EventProductVersion	Optional	String	The version of the product generating the event.
        # EventVendor	Mandatory	String	The vendor of the product generating the event. The value should be one of the values listed in Vendors and Products.
        # EventSchema	Mandatory	String	The schema the event is normalized to. Each schema documents its schema name.
        # EventSchemaVersion	Mandatory	String	The version of the schema. Each schema documents its current version.
        # EventReportUrl	Optional	String	A URL provided in the event for a resource that provides more information about the event.
        # EventOwner	Optional	String	The owner of the event, which is usually the department or subsidiary in which it was generated.
        # Device fields...
        # Dvc	Alias	String	A unique identifier of the device on which the event occurred or which reported the event, depending on the schema.
        # DvcIpAddr	Recommended	IP address	The IP address of the device on which the event occurred or which reported the event, depending on the schema.
        # DvcHostname	Recommended	Hostname	The hostname of the device on which the event occurred or which reported the event, depending on the schema.
        # DvcDomain	Recommended	String	The domain of the device on which the event occurred or which reported the event, depending on the schema.
        # DvcDomainType	Conditional	Enumerated	The type of DvcDomain. For a list of allowed values and further information, refer to DomainType.
        # DvcFQDN	Optional	String	The hostname of the device on which the event occurred or which reported the event, depending on the schema.
        # DvcDescription	Optional	String	A descriptive text associated with the device. For example: Primary Domain Controller.
        # DvcId	Optional	String	The unique ID of the device on which the event occurred or which reported the event, depending on the schema.
        # DvcIdType	Conditional	Enumerated	The type of DvcId. For a list of allowed values and further information, refer to DvcIdType.
        # DvcMacAddr	Optional	MAC	The MAC address of the device on which the event occurred or which reported the event.
        # DvcZone	Optional	String	The network on which the event occurred or which reported the event, depending on the schema. The zone is defined by the reporting device.
        # DvcOs	Optional	String	The operating system running on the device on which the event occurred or which reported the event.
        # DvcOsVersion	Optional	String	The version of the operating system on the device on which the event occurred or which reported the event.
        # DvcAction	Recommended	String	For reporting security systems, the action taken by the system, if applicable.
        # DvcOriginalAction	Optional	String	The original DvcAction as provided by the reporting device.
        # DvcInterface	Optional	String	The network interface on which data was captured. This field is typically relevant to network related activity, which is captured by an intermediate or tap device.
        # DvcScopeId	Optional	String	The cloud platform scope ID the device belongs to. DvcScopeId map to a subscription ID on Azure and to an account ID on AWS.
        # DvcScope	Optional	String	The cloud platform scope the device belongs to. DvcScope map to a subscription ID on Azure and to an account ID on AWS.
        # Other fields...
        # AdditionalFields	Optional	Dynamic	If your source provides additional information worth preserving, either keep it with the original field names or create the dynamic AdditionalFields field, and add to it the extra information as key/value pairs.
        # ASimMatchingIpAddr	Recommended	String	When a parser uses the ipaddr_has_any_prefix filtering parameters, this field is set with the one of the values SrcIpAddr, DstIpAddr, or Both to reflect the matching fields or fields.
        # ASimMatchingHostname	Recommended	String	When a parser uses the hostname_has_any filtering parameters, this field is set with the one of the values SrcHostname, DstHostname, or Both to reflect the matching fields or fields.

    def test_system_formatter_logs_process_event_fields(self):
        logger, log_buffer = self._create_logger("django")

        logger.debug("Does not matter")

        json_output = log_buffer.getvalue()
        output = json.loads(json_output)
        assert output["EventType"] == "ProcessCreated"
        assert output["EventSchemaVersion"] == "0.1.4"
        assert output["EventSchema"] == "ProcessEvent"

    # def test_request_formatting(self):
    #     output = self._create_request_log()
    #
    #     assert output["event"]["message"] == "Request test"

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
