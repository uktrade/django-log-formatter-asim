import json
import logging
import os
import platform
from urllib.parse import urlparse
from datetime import datetime

from django.conf import settings


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
            # Other fields...
            "AdditionalFields": json.dumps(record, default=lambda o: vars(o)),
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


class ASIMRequestFormatter(ASIMFormatterBase):
    def get_log_dict(self):
        log_dict = self._get_log_dict_base()

        request = self.record.request

        # Source fields...
        log_dict["Src"] = None
        log_dict["SrcIpAddr"] = request.environ.get("REMOTE_ADDR", None)
        log_dict["IpAddr"] = log_dict["SrcIpAddr"]
        log_dict["SrcPortNumber"] = request.environ.get("SERVER_PORT", None)
        log_dict["SrcHostname"] = None
        log_dict["SrcHostname"] = None
        log_dict["SrcDomain"] = None
        log_dict["SrcDomainType"] = None
        log_dict["SrcFQDN"] = None
        # Todo: Unsure of correct property for the user agent...
        # Might come from the following in order of priority
        #     request.user_agent
        #     request.headers.user_agent
        #     request.META.HTTP_USER_AGENT?
        # Probably need tests for all three
        log_dict["SrcDescription"] = getattr(request.headers, "USER_AGENT", None)
        log_dict["SrcDvcId"] = None
        log_dict["SrcDvcScopeId"] = None
        log_dict["SrcDvcScope"] = None
        log_dict["SrcDvcIdType"] = None
        log_dict["SrcDeviceType"] = None
        log_dict["SrcSubscriptionId"] = None
        log_dict["SrcGeoCountry"] = None
        log_dict["SrcGeoCity"] = None
        log_dict["SrcGeoLatitude"] = None
        log_dict["SrcGeoLongitude"] = None

        # Todo: Zipkin/Jeager headers are specific to cloudfoundry/gov uk paas. We might want to use the aws trace headers: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-request-tracing.html

        # parsed_url = urlparse(self.record.request.build_absolute_uri())
        #
        # ip = self._get_ip_address(self.record.request)
        #
        # request_bytes = len(self.record.request.body)
        #
        # logger_event.url(
        #     path=parsed_url.path,
        #     domain=parsed_url.hostname,
        # ).source(
        #     ip=self._get_ip_address(self.record.request)
        # ).http_response(status_code=getattr(self.record, "status_code", None)).client(
        #     address=ip,
        #     bytes=request_bytes,
        #     domain=parsed_url.hostname,
        #     ip=ip,
        #     port=parsed_url.port,
        # ).http_request(
        #     body_bytes=request_bytes,
        #     body_content=self.record.request.body,
        #     method=self.record.request.method,
        # )

        user = getattr(request, "user", None)
        user_id = None
        username = None
        if user:
            user_id = getattr(user, "id", None)
            if getattr(settings, "DLFE_LOG_SENSITIVE_USER_DATA", False):
                username = getattr(user, "username", getattr(user, "email", None))
            else:
                username = "REDACTED"
        log_dict["SrcUserId"] = user_id
        log_dict["SrcUsername"] = username

        return log_dict

    def _get_user_agent(self):
        return getattr(
            self.record.request.headers,
            "user_agent",
            None,
        )

    def _get_ip_address(self, request):
        # Import here as ipware uses settings
        from ipware import get_client_ip

        client_ip, is_routable = get_client_ip(request)
        return client_ip or "Unknown"


ASIM_FORMATTERS = {
    "root": ASIMSystemFormatter,
    "django.request": ASIMRequestFormatter,
}


class ASIMFormatter(logging.Formatter):
    def format(self, record):
        if record.name in ASIM_FORMATTERS:
            asim_formatter = ASIM_FORMATTERS[record.name]
        else:
            asim_formatter = ASIMSystemFormatter

        formatter = asim_formatter(record=record)

        log_dict = formatter.get_log_dict()

        return json.dumps(log_dict)
