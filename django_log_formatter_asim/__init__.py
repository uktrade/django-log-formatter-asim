import json
import logging
import os
import platform
from urllib.parse import urlparse
from datetime import datetime

from django.conf import settings

# # TODO: Event categories - https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html  # noqa E501
# CATEGORY_DATABASE = "database"
# CATEGORY_PROCESS = "process"
# CATEGORY_WEB = "web"


# class ASIMLogger(Logger):
#     def __init__(self, *args, **kwargs):
#         super(ASIMLogger, self).__init__(*args, **kwargs)
#
#     def get_log_dict(self):
#         log_dict = {
#             "EventMessage": self._base.event.message
#         }
#         return log_dict


class ASIMFormatterBase:
    def __init__(self, record):
        self.record = record

    def _get_log_dict_base(self):
        record = self.record
        log_time = datetime.utcfromtimestamp(record.created).isoformat()
        # See test_django_log_formatter.py for comments and thinking around these
        log_dict = {
            # Event fields...
            "EventMessage": record.msg,
            "EventCount": 1,
            "EventStartTime": log_time,
            "EventEndTime": log_time,
            "EventType": "ProcessCreated",
            "EventSubType": None,
            "EventResult": "NA",
            "EventResultDetails": None,
            "EventUid": None,
            "EventOriginalUid": None,
            "EventOriginalType": None,
            "EventOriginalSubType": None,
            "EventOriginalResultDetails": None,
            "EventSeverity": self._get_event_severity(record.levelname),
            "EventOriginalSeverity": record.levelname,
            "EventProduct": "Django",
            "EventProductVersion": None,
            "EventVendor": "Django",
            "EventSchema": "ProcessEvent",
            "EventSchemaVersion": "0.1.4",
            "EventReportUrl": None,
            "EventOwner": None,
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
            "AdditionalFields": json.dumps(record.__dict__),
            "ASimMatchingIpAddr": None,
            "ASimMatchingHostname": None,
        }
        return log_dict

    def _get_event_severity(self, log_level):
        map = {
            "DEBUG": "Informational",
            "INFO": "Informational",
            "WARNING": "Low",
            "ERROR": "Medium",
            "CRITICAL": "High",
        }
        return map[log_level]

    # def _get_event_base(self, extra_labels={}):
    #     labels = {
    #         "application": getattr(settings, "DLFE_APP_NAME", None),
    #         "env": self._get_environment(),
    #     }
    #
    #     logger = (
    #         ASIMLogger()
    #         .event(
    #             category=self._get_event_category(),
    #             action=self.record.name,
    #             message=self.record.getMessage(),
    #             labels={
    #                 **labels,
    #                 **extra_labels,
    #             },
    #         )
    #         .host(
    #             architecture=platform.machine(),
    #         )
    #     )
    #
    #     return logger

    # def _get_event_category(self):
    #     if self.record.name in ("django.request", "django.server"):
    #         return CATEGORY_WEB
    #     if self.record.name.startswith("django.db.backends"):
    #         return CATEGORY_DATABASE
    #
    #     return CATEGORY_PROCESS

    # def _get_environment(self):
    #     return os.getenv("DJANGO_SETTINGS_MODULE") or "Unknown"


class ASIMSystemFormatter(ASIMFormatterBase):
    def get_log_dict(self):
        return self._get_log_dict_base()


class ASIMDBFormatter(ASIMFormatterBase):
    # created for augmentation based on django.db.backends
    def get_log_dict(self):
        return self._get_log_dict_base()


# class ASIMRequestFormatter(ASIMFormatterBase):
#     def get_event(self):
#         zipkin_headers = getattr(
#             settings,
#             "DLFE_ZIPKIN_HEADERS",
#             ("X-B3-TraceId", "X-B3-SpanId"),
#         )
#
#         extra_labels = {}
#
#         for zipkin_header in zipkin_headers:
#             if getattr(
#                 self.record.request.headers,
#                 zipkin_header,
#                 None,
#             ):
#                 extra_labels[zipkin_header] = self.record.request.headers[
#                     zipkin_header
#                 ]  # noqa E501
#
#         logger_event = self._get_event_base(
#             extra_labels=extra_labels,
#         )
#
#         parsed_url = urlparse(self.record.request.build_absolute_uri())
#
#         ip = self._get_ip_address(self.record.request)
#
#         request_bytes = len(self.record.request.body)
#
#         logger_event.url(
#             path=parsed_url.path,
#             domain=parsed_url.hostname,
#         ).source(
#             ip=self._get_ip_address(self.record.request)
#         ).http_response(status_code=getattr(self.record, "status_code", None)).client(
#             address=ip,
#             bytes=request_bytes,
#             domain=parsed_url.hostname,
#             ip=ip,
#             port=parsed_url.port,
#         ).http_request(
#             body_bytes=request_bytes,
#             body_content=self.record.request.body,
#             method=self.record.request.method,
#         )
#
#         user_agent_string = getattr(
#             self.record.request.headers,
#             "user_agent",
#             None,
#         )
#
#         if not user_agent_string and "HTTP_USER_AGENT" in self.record.request.META:  # noqa E501
#             user_agent_string = self.record.request.META["HTTP_USER_AGENT"]
#
#         # Check for use of django-user_agents
#         if getattr(self.record.request, "user_agent", None):
#             logger_event.user_agent(
#                 device={
#                     "name": self.record.request.user_agent.device.family,
#                 },
#                 name=self.record.request.user_agent.browser.family,
#                 original=user_agent_string,
#                 version=self.record.request.user_agent.browser.version_string,
#             )
#         elif user_agent_string:
#             logger_event.user_agent(
#                 original=user_agent_string,
#             )
#
#         if getattr(self.record.request, "user", None):
#             if getattr(settings, "DLFE_LOG_SENSITIVE_USER_DATA", False):
#                 # Defensively check for full name due to possibility of custom user app
#                 try:
#                     full_name = self.record.request.user.get_full_name()
#                 except AttributeError:
#                     full_name = None
#
#                 # Check user attrs to account for custom user apps
#                 logger_event.user(
#                     email=getattr(self.record.request.user, "email", None),
#                     full_name=full_name,
#                     name=getattr(self.record.request.user, "username", None),
#                     id=getattr(self.record.request.user, "id", None),
#                 )
#             else:
#                 logger_event.user(
#                     id=getattr(self.record.request.user, "id", None),
#                 )
#
#         return logger_event
#
#     def _get_ip_address(self, request):
#         # Import here as ipware uses settings
#         from ipware import get_client_ip
#
#         client_ip, is_routable = get_client_ip(request)
#         return client_ip or "Unknown"


ASIM_FORMATTERS = {
    "root": ASIMSystemFormatter,
    # "django.request": ASIMRequestFormatter,
    "django.db.backends": ASIMSystemFormatter,
}


class ASIMFormatter(logging.Formatter):
    def format(self, record):
        if record.name in ASIM_FORMATTERS:
            asim_formatter = ASIM_FORMATTERS[record.name]
        else:
            asim_formatter = ASIMSystemFormatter

        formatter = asim_formatter(record=record)
        # logger_event = formatter.get_event()
        #
        # logger_event.log(
        #     level=self._get_severity(record.levelname),
        # )
        #
        # log_dict = {
        #     "EventMessage": record.msg
        # }

        log_dict = formatter.get_log_dict()

        return json.dumps(log_dict)

    # def _get_severity(self, level):
    #     if level == "DEBUG":
    #         return Severity.DEBUG
    #     elif level == "INFO":
    #         return Severity.INFO
    #     elif level == "WARNING":
    #         return Severity.WARNING
    #     elif level == "ERROR":
    #         return Severity.ERROR
    #     elif level == "CRITICAL":
    #         return Severity.CRITICAL
