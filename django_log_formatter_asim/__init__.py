import json
import logging
from datetime import datetime
from importlib.metadata import distribution

from django.conf import settings


class ASIMRootFormatter:
    def __init__(self, record):
        self.record = record

        if not getattr(settings, "DLFA_LOG_PERSONALLY_IDENTIFIABLE_INFORMATION", False):
            self._replace_personally_identifiable_information()

    def _replace_personally_identifiable_information(self):
        if getattr(self.record, "request", None):
            user = getattr(self.record.request, "user", None)
            if user:
                user.password = "{{PASSWORD}}"

    def get_log_dict_with_raw(self, log_dict):
        copied_dict = log_dict.copy()
        copied_dict["AdditionalFields"]["RawLog"] = json.dumps(self.record, default=self._to_dict)

        return copied_dict

    def get_log_dict(self):
        record = self.record
        log_time = datetime.utcfromtimestamp(record.created).isoformat()
        log_dict = {
            # Event fields...
            "EventMessage": record.msg,
            "EventCount": 1,
            "EventStartTime": log_time,
            "EventEndTime": log_time,
            "EventType": record.name,
            "EventResult": "NA",
            "EventSeverity": self._get_event_severity(record.levelname),
            "EventOriginalSeverity": record.levelname,
            "EventSchema": "ProcessEvent",
            "EventSchemaVersion": "0.1.4",
            "ActingAppType": "Django",
            # Other fields...
            "AdditionalFields": {
                "DjangoLogFormatterAsimVersion": distribution("django-log-formatter-asim").version,
                "TraceHeaders": {},
            },
        }

        if getattr(settings, "DLFA_INCLUDE_RAW_LOG", False):
            return self.get_log_dict_with_raw(log_dict)

        return log_dict

    def _to_dict(self, object):
        try:
            return vars(object)
        except TypeError:
            return str(object)

    def _get_event_severity(self, log_level):
        map = {
            "DEBUG": "Informational",
            "INFO": "Informational",
            "WARNING": "Low",
            "ERROR": "Medium",
            "CRITICAL": "High",
        }
        return map[log_level]


class ASIMRequestFormatter(ASIMRootFormatter):
    def _serialize_user(self, user):
        serialized_user = vars(user).copy()
        if "date_joined" in serialized_user:
            serialized_user["date_joined"] = serialized_user["date_joined"].isoformat()

        return {
            "username": serialized_user.get("username", None),
            "email": serialized_user.get("email", None),
            "first_name": serialized_user.get("first_name", None),
            "last_name": serialized_user.get("last_name", None),
            "password": serialized_user.get("password"),
            "date_joined": serialized_user.get("date_joined"),
            "is_active": serialized_user.get("is_active"),
            "is_staff": serialized_user.get("is_staff"),
            "is_superuser": serialized_user.get("is_superuser"),
        }

    def _serialize_request(self, request):
        return {
            "method": request.method,
            "path": request.path,
            "GET": dict(request.GET),
            "POST": dict(request.POST),
            "headers": dict(request.headers),
            "user": self._serialize_user(request.user),
        }

    def get_log_dict_with_raw(self, log_dict):
        copied_dict = log_dict.copy()
        serialized_request = self._serialize_request(self.record.request)

        record_dict = vars(self.record).copy()
        record_dict["request"] = serialized_request
        copied_dict["AdditionalFields"]["RawLog"] = json.dumps(record_dict)

        return copied_dict

    def get_log_dict(self):
        log_dict = super().get_log_dict()

        request = self.record.request

        # Source fields...
        log_dict["SrcIpAddr"] = request.headers.get("REMOTE_ADDR", None)
        log_dict["IpAddr"] = log_dict["SrcIpAddr"]
        log_dict["SrcPortNumber"] = request.environ.get("SERVER_PORT", None)
        user_id, username = self._get_user_details(request)
        log_dict["SrcUserId"] = user_id
        log_dict["SrcUsername"] = username

        # Acting Application fields...
        log_dict["HttpUserAgent"] = self._get_user_agent()

        # Additional fields...
        for trace_header in getattr(settings, "DLFA_TRACE_HEADERS", ("X-Amzn-Trace-Id",)):
            log_dict["AdditionalFields"]["TraceHeaders"][trace_header] = request.headers.get(
                trace_header, None
            )

        return log_dict

    def _get_user_details(self, request):
        user_id = None
        username = None
        user = getattr(request, "user", None)
        if user:
            user_id = getattr(user, "id", None)
            if user.is_anonymous:
                username = "AnonymousUser"
            else:
                username = getattr(user, "username", None)
                if not username:
                    username = getattr(user, "email", None)
        return user_id, username

    def _get_user_agent(self):
        request = self.record.request
        http_user_agent = getattr(request, "user_agent", None)
        if not http_user_agent:
            http_user_agent = getattr(request.headers, "User-Agent", None)
        if not http_user_agent:
            http_user_agent = request.META.get("HTTP_USER_AGENT", None)
        return http_user_agent

    def _get_ip_address(self, request):
        # Import here as ipware uses settings
        from ipware import get_client_ip

        client_ip, is_routable = get_client_ip(request)
        return client_ip or "Unknown"


ASIM_FORMATTERS = {
    "root": ASIMRootFormatter,
    "django.request": ASIMRequestFormatter,
}


class ASIMFormatter(logging.Formatter):
    def format(self, record):
        if record.name in ASIM_FORMATTERS:
            asim_formatter = ASIM_FORMATTERS[record.name]
        else:
            asim_formatter = ASIMRootFormatter

        formatter = asim_formatter(record=record)

        log_dict = formatter.get_log_dict()

        return json.dumps(log_dict)
