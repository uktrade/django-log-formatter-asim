import json
import logging
from datetime import datetime

from django.conf import settings


class ASIMFormatterBase:
    def __init__(self, record):
        self.record = record

    def _get_log_dict_base(self):
        record = self.record
        log_time = datetime.utcfromtimestamp(record.created).isoformat()
        log_dict = {
            # Event fields...
            "EventMessage": record.msg,
            "EventCount": 1,
            "EventStartTime": log_time,
            "EventEndTime": log_time,
            "EventType": "ProcessCreated",
            "EventResult": "NA",
            "EventSeverity": self._get_event_severity(record.levelname),
            "EventOriginalSeverity": record.levelname,
            "EventSchema": "ProcessEvent",
            "EventSchemaVersion": "0.1.4",
            "ActingAppType": "Django",
            # Other fields...
            "AdditionalFields": json.dumps(record, default=lambda o: vars(o)),
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


class ASIMSystemFormatter(ASIMFormatterBase):
    def get_log_dict(self):
        return self._get_log_dict_base()


class ASIMRequestFormatter(ASIMFormatterBase):
    def get_log_dict(self):
        log_dict = self._get_log_dict_base()

        request = self.record.request

        # Source fields...
        log_dict["SrcIpAddr"] = request.environ.get("REMOTE_ADDR", None)
        log_dict["IpAddr"] = log_dict["SrcIpAddr"]
        log_dict["SrcPortNumber"] = request.environ.get("SERVER_PORT", None)

        # Acting Application fields...
        log_dict["HttpUserAgent"] = self._get_user_agent()

        user_id, username = self._get_user_details(request)
        log_dict["SrcUserId"] = user_id
        log_dict["SrcUsername"] = username

        return log_dict

    def _get_user_details(self, request):
        user_id = None
        username = None
        user = getattr(request, "user", None)
        if user:
            user_id = getattr(user, "id", None)
            if user.__class__.__name__ == "AnonymousUser":
                username = "AnonymousUser"
            elif getattr(settings, "DLFA_LOG_SENSITIVE_USER_DATA", False):
                username = getattr(user, "username", None)
                if not username:
                    username = getattr(user, "email", None)
            else:
                username = "REDACTED"
        return user_id, username

    def _get_user_agent(self):
        request = self.record.request
        http_user_agent = getattr(request, "user_agent", None)
        if not http_user_agent:
            http_user_agent = getattr(request.headers, "user_agent", None)
        if not http_user_agent:
            http_user_agent = request.META.get("HTTP_USER_AGENT", None)
        return http_user_agent

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
