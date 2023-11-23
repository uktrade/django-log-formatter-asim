# Django ASIM log formatter

The library formats Django logs in [ASIM format](https://learn.microsoft.com/en-us/azure/sentinel/normalization).

Mapping to the format may not be complete, but best effort has been made to create logical field mappings.

If you need to amend the mapping, you can implement a custom formatter.

## Installation

``` shell
pip install django-log-formatter-asim
```

## Usage

Using in a Django logging configuration:

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
    "loggers": {
        "django": {
            "handlers": ["asim"],
            ...
        },
    },
}
```

## Dependencies

This package uses [Django IPware](https://github.com/un33k/django-ipware) for IP address capture.

This package is compatible with [Django User Agents](https://pypi.org/project/django-user-agents) which, when used, will enhance logged user agent information.

## Settings

`DLFA_LOG_PERSONALLY_IDENTIFIABLE_INFORMATION` - the formatter checks this setting to see if personally identifiable information should be logged. If this is not set to true, only the user's id is logged.

`DLFA_TRACE_HEADERS` - used for defining custom zipkin headers, the defaults is `("X-Amzn-Trace-Id")`, but for applications hosted in GOV.UK PaaS you should use `("X-B3-TraceId", "X-B3-SpanId")`. If you are running your application in both places side by side during migration, the following should work in your Django settings:

`DLFA_INCLUDE_RAW_LOG` - By default the original unformatted log is not included in the ASIM formatted log. You can enable that by setting this to `True` and it will be included in `AddidtionalFields.RawLog`.

```python
from dbt_copilot_python.utility import is_copilot

if is_copilot():
   DLFA_TRACE_HEADERS = ("X-B3-TraceId", "X-B3-SpanId")
```

## Formatter classes

``` python
    ASIM_FORMATTERS = {
        "root": ASIMSystemFormatter,
        "django.request": ASIMRequestFormatter,
    }
```

The default class for other loggers is:

``` python
    ASIMSystemFormatter
```

## Creating a custom formatter

If you wish to create your own ASIM formatter, you can inherit from ASIMSystemFormatter and call _get_event_base to get the base level logging data for use in augmentation:

``` python
    class ASIMSystemFormatter(ASIMFormatterBase):
        def get_event(self):
            logger_event = self._get_event_base()

            # Customise logger event

            return logger_event
```

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
