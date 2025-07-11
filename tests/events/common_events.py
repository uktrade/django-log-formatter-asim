import json
from abc import ABC
from abc import abstractmethod
from collections import namedtuple


class CommonEvents(ABC):
    def test_does_not_populate_request_environ_fields_when_environ_is_not_provided(self, capsys):
        wsgi_request = namedtuple("Request", ["user", "session"])(
            namedtuple("User", ["username"])(None),
            namedtuple("Session", ["session_key"])(None),
        )

        self.generate_event(wsgi_request)

        structured_log_entry = self._get_structured_log_entry(capsys)

        assert "DvcHostname" not in structured_log_entry
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
