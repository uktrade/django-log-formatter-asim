import json
import os
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

        assert "TargetAppName" not in structured_log_entry
        assert "TargetUrl" not in structured_log_entry
        assert "HttpHost" not in structured_log_entry
        assert "SrcIpAddr" not in structured_log_entry

    def test_populates_TargetContainerId_when_environment_variable_available(
        self, wsgi_request, capsys
    ):
        os.environ["ECS_CONTAINER_METADATA_URI"] = "http://blah/testid"
        self.generate_event(wsgi_request)
        del os.environ["ECS_CONTAINER_METADATA_URI"]
        structured_log_entry = self._get_structured_log_entry(capsys)

        assert structured_log_entry["TargetContainerId"] == "testid"

    def test_does_not_populate_TargetContainerId_when_environment_variable_not_set(
        self, wsgi_request, capsys
    ):
        self.generate_event(wsgi_request)

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert "TargetContainerId" not in structured_log_entry

    def test_does_not_expect_user_property_to_exist_on_request(self, wsgi_request, capsys):
        # If the Django AuthenticationMiddleware has not been installed, then no
        # user property will exist on wsgi_request.
        del wsgi_request.user

        self.generate_event(wsgi_request)

        structured_log_entry = self._get_structured_log_entry(capsys)
        assert "TargetUsername" not in structured_log_entry

    @abstractmethod
    def generate_event(self, wsgi_request):
        pass

    def _get_structured_log_entry(self, capsys):
        (out, _) = capsys.readouterr()
        self._assert_has_one_new_line_at_end_of_string(out)
        return json.loads(out)

    def _assert_has_one_new_line_at_end_of_string(self, expected):
        assert expected.find("\n") == len(expected) - 1
