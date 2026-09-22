"""Shared Python framework target parsing."""

import os
import unicodedata

from ..model import TARGET_FILE, TARGET_MODULE, TARGET_NONE


GENERIC_MODULE_NAMES = {
    "api", "app", "application", "asgi", "celery", "cli", "conf", "config",
    "entrypoint", "index", "manage", "models", "project", "routes", "run",
    "runserver", "server", "service", "settings", "src", "start", "tasks",
    "urls", "views", "web", "worker", "wsgi",
}


def clean_value(value):
    """Return a trimmed value without control characters."""
    value = (value or "").strip()
    if not value or any(unicodedata.category(char) == "Cc" for char in value):
        return ""
    return value


def valid_identifier(value):
    """Recognize the identifier form accepted by OBI."""
    if not value:
        return False
    for index, char in enumerate(value):
        category = unicodedata.category(char)
        if index == 0 and char != "_" and not category.startswith("L"):
            return False
        if index and char != "_" and not category.startswith("L") and category != "Nd":
            return False
    return True


def valid_module(value):
    """Recognize a dotted Python module name."""
    return bool(value) and all(valid_identifier(part) for part in value.split("."))


def application_reference(value, strict=False):
    """Recognize a module and application object reference."""
    if value.count(":") != 1:
        return False
    module, obj = value.split(":", 1)
    if not strict and "(" in obj:
        obj = obj.split("(", 1)[0]
    return valid_module(module) and valid_module(obj)


def first_application_reference(values):
    """Return the first valid application reference."""
    return next((value for value in values if application_reference(value)), "")


def target_reference(target):
    """Remove an application object from a launch target."""
    return (target or "").strip().split(":", 1)[0].strip()


def classify_target(target):
    """Classify a framework target as a file or module."""
    target = target_reference(target)
    if not target:
        return TARGET_NONE
    if os.path.isabs(target) or "/" in target or "\\" in target or target.lower().endswith(".py"):
        return TARGET_FILE
    return TARGET_MODULE


def target_name(target):
    """Derive a specific service name from an application target."""
    target = target_reference(target)
    if not target:
        return ""
    target = target.replace("\\", "/")
    if "/" in target:
        target = os.path.splitext(target.rsplit("/", 1)[-1])[0]
    elif target.lower().endswith(".py"):
        target = os.path.splitext(target)[0]
    parts = target.split(".")
    for index, part in enumerate(parts):
        if part.lower() == "settings" and index:
            return _specific_name(parts[index - 1])
    for part in reversed(parts):
        name = _specific_name(part)
        if name:
            return name
    return ""


def _specific_name(value):
    """Reject generic module segments as service names."""
    value = clean_value(value)
    if value in {"", ".", "..", "-", "__init__", "__main__"}:
        return ""
    return "" if value.lower() in GENERIC_MODULE_NAMES else value

