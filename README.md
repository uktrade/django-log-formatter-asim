# Django ASIM log formatter

The library formats Django logs in [ASIM format](https://learn.microsoft.com/en-us/azure/sentinel/normalization).

Mapping to the format may not be complete, but best effort has been made to create logical field mappings.

## Installation

``` shell
pip install django-log-formatter-asim
```

## Usage

This package provides the following ASIM functionality:

- A Python [logging.Formatter] implementation.
- A module of functions `django_log_formatter_asim.events` which generate ASIM event log entries.

[logging.Formatter]: https://docs.python.org/3/library/logging.html#formatter-objects

### `logging.Formatter` setup

Using the formatter in a Django logging configuration:

``` python
from django_log_formatter_asim import ASIMFormatter

LOGGING = {
    ...
    "formatters": {
        "asim_formatter": {
            "()": ASIMFormatter,
        },
    },
    'handlers': {
        'asim': {
            'formatter': 'asim_formatter',
            ...
        },
    },
    "root": {
        "handlers": ["asim"],
        ...
    }
    "loggers": {
        "django": {
            "handlers": ["asim"],
            "propagate": False
            ...
        },
    },
}
```

In this example we assign the ASIM formatter to a `handler` and ensure both `root` and `django` loggers use this `handler`.
We then set `propagate` to `False` on the `django` logger, to avoid duplicating logs at the root level.

### ASIM Events

The events mostly follow the Microsoft schema but have been tailored to Department of Business and Trade needs.

Events are designed for simple integrate into your Django app.
Each will take additional information from the [Django HttpRequest object][django-request].

[django-request]: https://docs.djangoproject.com/en/5.2/ref/request-response/#httprequest-objects

#### Authentication event

Following the [ASIM Authentication Schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-authentication).

```python
# Example usage
from django_log_formatter_asim.events import log_authentication

log_authentication(
    request,
    event=log_authentication.Event.Logoff,
    result=log_authentication.Result.Success,
    login_method=log_authentication.LoginMethod.UsernamePassword,
)

# Example JSON printed to standard output
{
    # Values provided as arguments
    "EventType": "Logoff",
    "EventResult": "Success",
    "LogonMethod": "Username & Password",

    # Calculated / Hard coded fields
    "EventStartTime": "2025-07-02T08:15:20+00:00",
    "EventSeverity": "Informational",
    "EventOriginalType": "001c",
    "EventSchema": "Authentication",
    "EventSchemaVersion": "0.1.4",

    # Taken from Django HttpRequest object
    "HttpHost": "WebServer.local",
    "SrcIpAddr": "192.168.1.101",
    "TargetUrl": "https://WebServer.local/steel",
    "TargetSessionId": "def456",
    "TargetUsername": "Adrian"

    # Taken from DBT Platform environment variables
    "TargetAppName": "export-analytics-frontend",
}
```

#### File Activity event

Following the [ASIM File Event Schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-file-event).

```python
# Example usage
from django_log_formatter_asim.events import log_file_activity

log_file_activity(
    request,
    event=log_file_activity.Event.FileCopied,
    result=log_file_activity.Result.Success,
    file={
        "path": "/tmp/copied.txt",
        "content_type": "text/plain",
        "extension": "txt",
        "name": "copied.txt",
        "sha256": "6798b7a132f37a0474002dec538ec52bdcd5f7b76e49e52c8a3d2016ca8d1d18",
        "size": 14,
    },
    # source_file is only necessary if the event is one of FileRenamed, FileMoved, FileCopied, FolderMoved
    source_file={
        "path": "/tmp/original.txt",
        "content_type": "text/plain",
        "extension": "txt",
        "name": "original.txt",
        "sha256": "6798b7a132f37a0474002dec538ec52bdcd5f7b76e49e52c8a3d2016ca8d1d18",
        "size": 14,
    },
)

# Example JSON printed to standard output
{
    # Values provided as arguments
    "EventType": "FileCopied",
    "EventResult": "Success",

    "TargetFilePath": "/tmp/copied.txt",
    "TargetFileName": "copied.txt",
    "TargetFileExtension": "txt",
    "TargetFileMimeType": "text/plain",
    "TargetFileSHA256": "6798b7a132f37a0474002dec538ec52bdcd5f7b76e49e52c8a3d2016ca8d1d18",
    "TargetFileSize": 14,

    "SrcFilePath": "/tmp/original.txt",
    "SrcFileName": "original.txt",
    "SrcFileExtension": "txt",
    "SrcFileMimeType": "text/plain",
    "SrcFileSHA256": "6798b7a132f37a0474002dec538ec52bdcd5f7b76e49e52c8a3d2016ca8d1d18",
    "SrcFileSize": 14,

    # Calculated / Hard coded fields
    "EventStartTime": "2025-07-30T11:05:09.406460+00:00",
    "EventSchema": "FileEvent",
    "EventSchemaVersion": "0.2.1",
    "EventSeverity": "Informational",

    # Taken from Django HttpRequest object
    "HttpHost": "WebServer.local",
    "SrcIpAddr": "192.168.1.101",
    "TargetUrl": "https://WebServer.local/steel",
    "TargetUsername": "Adrian"

    # Taken from DBT Platform environment variables
    "TargetAppName": "export-analytics-frontend",
}
```

### Settings

`DLFA_LOG_PERSONALLY_IDENTIFIABLE_INFORMATION` - the formatter checks this setting to see if personally identifiable information should be logged. If this is not set to true, only the user's id is logged.

`DLFA_TRACE_HEADERS` - used for defining custom zipkin headers, the defaults is `("X-Amzn-Trace-Id")`, but for applications hosted in GOV.UK PaaS you should use `("X-B3-TraceId", "X-B3-SpanId")`. If you are running your application in both places side by side during migration, the following should work in your Django settings:

`DLFA_INCLUDE_RAW_LOG` - By default the original unformatted log is not included in the ASIM formatted log. You can enable that by setting this to `True` and it will be included in `AddidtionalFields.RawLog`.

```python
from dbt_copilot_python.utility import is_copilot

if is_copilot():
   DLFA_TRACE_HEADERS = ("X-B3-TraceId", "X-B3-SpanId")
```

### Serialisation behaviour

The package provides one `logging.Formatter` class, `ASIMFormatter` which routes log messages to a serialiser
which generates a python dict which the formatter converts to a JSON string and prints to standard output.

It has a generic serialiser called `ASIMRootFormatter` and a custom serlializer for log messages where the
logger is `django.request`.

``` python
    ASIM_FORMATTERS = {
        "root": ASIMRootFormatter,
        "django.request": ASIMRequestFormatter,
    }
```

#### ASIMRootFormatter

This serialiser outputs the following ASIM fields.

- `EventSchema` = `ProcessEvent`
- `ActingAppType` = `Django`
- `AdditionalFields[DjangoLogFormatterAsimVersion]`
- `EventSchemaVersion`
- `EventMessage`
- `EventCount`
- `EventStartTime`
- `EventEndTime`
- `EventType`
- `EventResult`
- `EventSeverity`
- `EventOriginalSeverity`

Additionally, the following DataDog fields where available:

- `dd.trace_id`
- `dd.span_id`
- `env`
- `service`
- `version`


#### ASIMRequestFormatter

This serialiser outputs the following ASIM fields in addition to the ones from ASIMRootFormatter.
It is coupled to the datastructure provided by the `django.request` logger.
The `django.request` logger only outputs requests where the response code is 4xx/5xx.

- `SrcIpAddr` and `IpAddr`
- `SrcPortNumber`
- `SrcUserId` and `SrcUsername`
- `HttpUserAgent`
- `AdditionalFields["TraceHeaders"][trace_header_name]` - See `DLFA_TRACE_HEADERS` setting for more information.

#### Creating a custom serialiser

If you wish to create your own ASIM serialiser, you can inherit from `ASIMRootFormatter` and call
`super().get_log_dict()` to get the base level logging data for augmentation:

``` python
    class MyASIMFormatter(ASIMRootFormatter):
        def get_log_dict(self):
            log_dict = super().get_log_dict()

            # Customise logger event

            return log_dict
```

This serialiser can then be added to `ASIM_FORMATTERS`...

```python
ASIM_FORMATTERS["my_logger"] = MyASIMFormatter
```

## Dependencies

This package uses [Django IPware](https://github.com/un33k/django-ipware) for IP address capture.

This package is compatible with [Django User Agents](https://pypi.org/project/django-user-agents) which, when used, will enhance logged user agent information.

## Contributing to the `django-log-formatter-asim` package

### Getting started

1. Clone the repository:

   ```
   git clone https://github.com/uktrade/django-log-formatter-asim.git && cd django-log-formatter-asim
   ```

2. Install the required dependencies:

   ```
   pip install poetry && poetry install && poetry run pre-commit install
   ```

### Testing

#### Automated testing

Run `poetry run pytest` in the root directory to run all tests.

Or, run `poetry run tox` in the root directory to run all tests for multiple Python versions. See the [`tox` configuration file](tox.ini).

### Publishing

1. Acquire API token from [Passman](https://passman.ci.uktrade.digital/secret/cc82a3f7-ddfa-4312-ab56-1ff8528dadc8/).
   - Request access from the SRE team.
   - _Note: You will need access to the `platform` group in Passman._
2. Run `poetry config pypi-token.pypi <token>` to add the token to your Poetry configuration.

Update the version, as the same version cannot be published to PyPI.

```
poetry version patch
```

More options for the `version` command can be found in the [Poetry documentation](https://python-poetry.org/docs/cli/#version). For example, for a minor version bump: `poetry version minor`.

Build the Python package.

```
poetry build
```

Publish the Python package.

_Note: Make sure your Pull Request (PR) is approved and contains the version upgrade in `pyproject.toml` before publishing the package._

```
poetry publish
```

Check the [PyPI Release history](https://pypi.org/project/django-log-formatter-asim/#history) to make sure the package has been updated.

For an optional manual check, install the package locally and test everything works as expected.