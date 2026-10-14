"""FastAPI CLI launch parsing."""

from ..model import Launch, TARGET_MODULE
from .common import application_reference, classify_target, clean_value


FASTAPI_WITH_VALUES = {
    "--host", "--port", "--uds", "--fd", "--app", "--entrypoint", "-e", "--root-path",
    "--forwarded-allow-ips", "--workers", "--reload-delay", "--reload-dir",
    "--reload-include", "--reload-exclude",
}
FASTAPI_WITHOUT_VALUES = {
    "--reload", "--no-reload", "--proxy-headers", "--no-proxy-headers", "--verbose", "-v", "--help", "-h",
}


def parse_fastapi(args, env):
    """Parse a FastAPI CLI launch."""
    for index, arg in enumerate(args):
        if arg not in {"run", "dev"}:
            if arg in {"--verbose", "--no-verbose"}:
                continue
            return Launch()
        parsed = _fastapi_arguments(args[index + 1:])
        if parsed is None:
            return Launch()
        positionals, entrypoint, explicit, app_option = parsed
        if explicit:
            if clean_value(entrypoint) != entrypoint or app_option or positionals or not application_reference(entrypoint, strict=True):
                return Launch()
            return Launch(target=entrypoint, target_kind=TARGET_MODULE, search_paths=["."])
        if not positionals:
            return Launch() if app_option else Launch(fastapi_auto=True)
        if len(positionals) != 1:
            return Launch()
        return Launch(target=positionals[0], target_kind=classify_target(positionals[0]))
    return Launch()


def _fastapi_arguments(args):
    """Parse FastAPI command options and positionals."""
    positionals = []
    entrypoint = ""
    explicit = False
    app_option = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return positionals + args[index + 1:], entrypoint, explicit, app_option
        if arg.startswith("--"):
            parsed = _fastapi_long_option(arg, args, index)
            if parsed is None:
                return None
            index, name, value = parsed
            if name == "--entrypoint":
                entrypoint, explicit = value, True
            elif name == "--app":
                app_option = True
        elif arg.startswith("-") and arg != "-":
            parsed = _fastapi_short_option(arg, args, index)
            if parsed is None:
                return None
            index, value = parsed
            if value is not None:
                entrypoint, explicit = value, True
        else:
            positionals.append(arg)
        index += 1
    return positionals, entrypoint, explicit, app_option


def _fastapi_long_option(arg, args, index):
    """Parse a FastAPI long option and its optional value."""
    name, separator, value = arg.partition("=")
    if name not in FASTAPI_WITH_VALUES:
        return (index, name, "") if name in FASTAPI_WITHOUT_VALUES and not separator else None
    if separator:
        return index, name, value
    index += 1
    if index == len(args):
        return None
    return index, name, args[index]


def _fastapi_short_option(arg, args, index):
    """Parse clustered FastAPI short options."""
    for offset in range(1, len(arg)):
        name = "-" + arg[offset]
        if name in FASTAPI_WITH_VALUES:
            value = arg[offset + 1:]
            if not value:
                index += 1
                if index == len(args):
                    return None
                value = args[index]
            return index, value if name == "-e" else None
        if name not in FASTAPI_WITHOUT_VALUES:
            return None
    return index, None

