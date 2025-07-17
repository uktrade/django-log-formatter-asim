import json
from abc import ABC
from abc import abstractmethod
from collections import namedtuple

from django.test import RequestFactory


class CommonEvents(ABC):
    def test_does_not_populate_srcip_and_httphost_when_META_is_not_provided(self, capsys):
        request_factory = RequestFactory()
        wsgi_request = request_factory.get("/")
        wsgi_request.user = namedtuple("User", ["username"])(None)
        wsgi_request.session = namedtuple("Session", ["session_key"])(None)
        wsgi_request.META.pop("REMOTE_ADDR", None)
        wsgi_request.META.pop("HTTP_HOST", None)

        self.generate_event(wsgi_request)

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert "TargetUrl" not in structured_log_entry
        assert "HttpHost" not in structured_log_entry
        assert "SrcIpAddr" not in structured_log_entry

    @abstractmethod
    def generate_event(self, wsgi_request):
        pass

    def _get_structured_log_entry(self, capsys):
        (out, _) = capsys.readouterr()
        self._assert_has_one_new_line_at_end_of_string(out)
        return json.loads(out)

    def _assert_has_one_new_line_at_end_of_string(self, expected):
        assert expected.find("\n") == len(expected) - 1
