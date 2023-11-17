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

        record = self.record

        # Source fields...
        log_dict["Src"] = None
        log_dict["SrcIpAddr"] = record.request.environ.get("REMOTE_ADDR", None)
        log_dict["IpAddr"] = log_dict["SrcIpAddr"]
        log_dict["SrcPortNumber"] = record.request.environ.get("SERVER_PORT", None)
        log_dict["SrcHostname"] = None
        log_dict["SrcHostname"] = None
        log_dict["SrcDomain"] = None
        log_dict["SrcDomainType"] = None
        log_dict["SrcFQDN"] = None
        # Todo: Unsure if correct property for the user agent...
        log_dict["SrcDescription"] = record.request.headers.USER_AGENT
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

        return log_dict

    def get_event(self):
        zipkin_headers = getattr(
            settings,
            "DLFE_ZIPKIN_HEADERS",
            ("X-B3-TraceId", "X-B3-SpanId"),
        )

        extra_labels = {}

        for zipkin_header in zipkin_headers:
            if getattr(
                self.record.request.headers,
                zipkin_header,
                None,
            ):
                extra_labels[zipkin_header] = self.record.request.headers[
                    zipkin_header
                ]  # noqa E501

        logger_event = self._get_event_base(
            extra_labels=extra_labels,
        )

        parsed_url = urlparse(self.record.request.build_absolute_uri())

        ip = self._get_ip_address(self.record.request)

        request_bytes = len(self.record.request.body)

        logger_event.url(
            path=parsed_url.path,
            domain=parsed_url.hostname,
        ).source(
            ip=self._get_ip_address(self.record.request)
        ).http_response(status_code=getattr(self.record, "status_code", None)).client(
            address=ip,
            bytes=request_bytes,
            domain=parsed_url.hostname,
            ip=ip,
            port=parsed_url.port,
        ).http_request(
            body_bytes=request_bytes,
            body_content=self.record.request.body,
            method=self.record.request.method,
        )

        user_agent_string = self._get_user_agent()

        if not user_agent_string and "HTTP_USER_AGENT" in self.record.request.META:  # noqa E501
            user_agent_string = self.record.request.META["HTTP_USER_AGENT"]

        # Check for use of django-user_agents
        if getattr(self.record.request, "user_agent", None):
            logger_event.user_agent(
                device={
                    "name": self.record.request.user_agent.device.family,
                },
                name=self.record.request.user_agent.browser.family,
                original=user_agent_string,
                version=self.record.request.user_agent.browser.version_string,
            )
        elif user_agent_string:
            logger_event.user_agent(
                original=user_agent_string,
            )

        if getattr(self.record.request, "user", None):
            if getattr(settings, "DLFE_LOG_SENSITIVE_USER_DATA", False):
                # Defensively check for full name due to possibility of custom user app
                try:
                    full_name = self.record.request.user.get_full_name()
                except AttributeError:
                    full_name = None

                # Check user attrs to account for custom user apps
                logger_event.user(
                    email=getattr(self.record.request.user, "email", None),
                    full_name=full_name,
                    name=getattr(self.record.request.user, "username", None),
                    id=getattr(self.record.request.user, "id", None),
                )
            else:
                logger_event.user(
                    id=getattr(self.record.request.user, "id", None),
                )

        return logger_event

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
