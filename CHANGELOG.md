# Changelog

## Unreleased

### Added

* Support for Django 6

### Removed

* Support for versions of Django which are end of life, below 4.2

## [1.2.0](https://github.com/uktrade/django-log-formatter-asim/compare/1.1.0...1.2.0) (2026-01-12)

### Added

* Add an ASIM events method `log_file_activity` for emitting cyber information.
  See also [usage example](README.md#file-activity-event), and the [method docstring](django_log_formatter_asim/events/file_activity.py).
* Add an ASIM events method `log_account_management` for emitting cyber information.
  See also [usage example](README.md#account-management-event), and the [method docstring](django_log_formatter_asim/events/account_management.py).
* Add support for `ddtrace` major version 4.

## [1.1.0](https://github.com/uktrade/django-log-formatter-asim/compare/1.0.0...1.1.0) (2025-07-22)


### Added

* Add module for logging ASIM events, with a method `log_authentication` for emitting cyber information.
  See also [usage example](README.md#authentication-event), and the [method docstring](django_log_formatter_asim/events/authentication.py).

## [1.0.0](https://github.com/uktrade/django-log-formatter-asim/compare/0.0.6...1.0.0) (2025-03-18)


### Added

* Add fields to logging.formatter enable Datadog logs correlation (DBTP-1661) ([#23](https://github.com/uktrade/django-log-formatter-asim/issues/23)) ([debf26a](https://github.com/uktrade/django-log-formatter-asim/commit/debf26a5dbce6e606c6b7f9569365d7e740f9115))

