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
In this example we assign the ASIM formatter to a `handler` and ensure both `root` and `django` loggers use this `handler`. We then set `propagate` to `False` on the `django` logger, to avoid duplicating logs at the root level. 

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