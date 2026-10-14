"""Shared command-line parsing for Python frameworks."""

from ..model import Launch, TARGET_MODULE
from .common import first_application_reference


def separated_option_value(value):
    """Check whether a token can safely be consumed as an option value."""
    if value == "-" or not value.startswith("-"):
        return True
    number = value[1:]
    if number.endswith(".") or number.count(".") > 1:
        return False
    digits = number.replace(".", "")
    return bool(digits) and digits.isdigit()


def short_option(arg, with_values, without_values):
    """Parse a cluster of argparse-style short options."""
    for index in range(1, len(arg)):
        name = "-" + arg[index]
        if name in without_values:
            continue
        if name in with_values:
            return index == len(arg) - 1, True
        return False, False
    return False, True


def argparse_positionals(args, with_values, without_values):
    """Collect positionals while validating all known options."""
    values = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return values + args[index + 1:]
        if arg.startswith("--"):
            name, separator, _ = arg.partition("=")
            if name in with_values:
                if not separator:
                    index += 1
                    if index == len(args) or not separated_option_value(args[index]):
                        return None
            elif name not in without_values or separator:
                return None
        elif arg.startswith("-") and arg != "-":
            consumes, known = short_option(arg, with_values, without_values)
            if not known:
                return None
            if consumes:
                index += 1
                if index == len(args) or not separated_option_value(args[index]):
                    return None
        else:
            values.append(arg)
        index += 1
    return values


def argparse_application(args, with_values, without_values):
    """Parse the first valid application reference from argparse positionals."""
    positionals = argparse_positionals(args, with_values, without_values)
    target = first_application_reference(positionals or [])
    if not target:
        return Launch()
    return Launch(target=target, target_kind=TARGET_MODULE, search_paths=["."])


def last_long_option(args, option, initial=""):
    """Return the last value supplied for a long option."""
    value = initial
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == option and index + 1 < len(args):
            index += 1
            value = args[index]
        elif arg.startswith(option + "="):
            value = arg[len(option) + 1:]
        index += 1
    return value

