"""Gunicorn launch parsing."""

import os

from ..model import Launch, TARGET_MODULE
from .arguments import short_option
from .common import application_reference, clean_value, valid_module


GUNICORN_WITH_VALUES = set("""
-c --config -b --bind --backlog -w --workers -k --worker-class --threads
--worker-connections --max-requests --max-requests-jitter -t --timeout --graceful-timeout
--keep-alive --limit-request-line --limit-request-fields --limit-request-field_size
--reload-engine --reload-extra-file --chdir -e --env -p --pid --worker-tmp-dir
-u --user -g --group -m --umask --forwarded-allow-ips --access-logfile
--access-logformat --error-logfile --log-file --log-level --logger-class --log-config
--log-config-json --log-syslog-to --log-syslog-prefix --log-syslog-facility --statsd-host
--dogstatsd-tags --statsd-prefix -n --name --pythonpath --paste --paster
--proxy-allow-from --protocol --uwsgi-allow-from --keyfile --certfile --ssl-version
--cert-reqs --ca-certs --ciphers --http-protocols --http2-cleartext
--http2-max-concurrent-streams --http2-initial-window-size --http2-max-frame-size
--http2-max-header-list-size --paste-global --forwarder-headers --header-map --asgi-loop
--asgi-lifespan --asgi-disconnect-grace-period --http-parser --root-path --dirty-app
--dirty-workers --dirty-timeout --dirty-threads --dirty-graceful-timeout --control-socket
--control-socket-mode
""".split())
GUNICORN_WITHOUT_VALUES = set("""
--reload --spew --check-config --print-config --preload --no-sendfile --reuse-port
-D --daemon --initgroups --disable-redirect-access-to-syslog --capture-output
--log-syslog -R --enable-stdio-inheritance --enable-backlog-metric --suppress-ragged-eofs
--do-handshake-on-connect --permit-obsolete-folding --strip-header-spaces
--permit-unconventional-http-method --permit-unconventional-http-version --casefold-http-method
--no-control-socket -h --help -v --version --proxy-protocol
""".split())


def parse_gunicorn(args, env):
    """Parse a Gunicorn launch."""
    env_args = _split_shell_fields(env.get("GUNICORN_CMD_ARGS", ""))
    if env_args is None or _gunicorn_positionals(env_args) is None:
        return Launch()
    positionals = _gunicorn_positionals(args)
    if positionals is None:
        return Launch()
    settings = {}
    _apply_gunicorn_settings(env_args, settings)
    _apply_gunicorn_settings(args, settings)
    app_dir = settings.get("chdir") or "."
    paths = _split_list(settings.get("pythonpath"))
    paths = [path if os.path.isabs(path) else os.path.join(app_dir, path) for path in reversed(paths)]
    launch = Launch(app_dir=app_dir, search_paths=paths + [app_dir], fallback_name=clean_value(settings.get("name")))
    if positionals and _gunicorn_application(positionals[0]):
        launch.target = positionals[0]
        launch.target_kind = TARGET_MODULE
    return launch


def _gunicorn_application(target):
    """Validate a Gunicorn application positional."""
    return clean_value(target) == target and (valid_module(target) or application_reference(target))


def _apply_gunicorn_settings(args, settings):
    """Apply Gunicorn path and name settings in argument order."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return
        for option, key in (("--chdir", "chdir"), ("--pythonpath", "pythonpath"), ("--name", "name"), ("-n", "name")):
            if arg == option and index + 1 < len(args):
                index += 1
                settings[key] = args[index]
                break
            if option.startswith("--") and arg.startswith(option + "="):
                settings[key] = arg[len(option) + 1:]
                break
        else:
            attached = _gunicorn_attached_name(arg)
            if attached is not None:
                settings["name"] = attached
        index += 1


def _gunicorn_attached_name(arg):
    """Read an attached Gunicorn short name option."""
    if not arg.startswith("-") or arg.startswith("--"):
        return None
    for index in range(1, len(arg)):
        name = "-" + arg[index]
        if name in GUNICORN_WITHOUT_VALUES:
            continue
        if name == "-n" and index + 1 < len(arg):
            return arg[index + 1:].lstrip("=")
        return None
    return None


def _gunicorn_positionals(args):
    """Collect Gunicorn positionals while validating options."""
    values = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return values + args[index + 1:]
        if arg.startswith("--"):
            name, separator, value = arg.partition("=")
            if name == "--proxy-protocol":
                if separator and value not in {"off", "v1", "v2", "auto"}:
                    return None
                if not separator and index + 1 < len(args) and args[index + 1] in {"off", "v1", "v2", "auto"}:
                    index += 1
            elif name in GUNICORN_WITH_VALUES:
                if not separator:
                    index += 1
                    if index == len(args):
                        return None
            elif name not in GUNICORN_WITHOUT_VALUES or separator:
                return None
        elif arg.startswith("-") and arg != "-":
            consumes, known = short_option(arg, GUNICORN_WITH_VALUES, GUNICORN_WITHOUT_VALUES)
            if not known:
                return None
            if consumes:
                index += 1
                if index == len(args):
                    return None
        else:
            values.append(arg)
        index += 1
    return values


def _split_shell_fields(value):
    """Split Gunicorn options supplied through the environment."""
    fields = []
    field = []
    quote = ""
    escaped = False
    started = False
    for char in value or "":
        if escaped:
            field.append(char)
            escaped = False
            started = True
        elif char == "\\" and quote != "'":
            escaped = True
            started = True
        elif quote:
            if char == quote:
                quote = ""
            else:
                field.append(char)
            started = True
        elif char in {'"', "'"}:
            quote = char
            started = True
        elif char.isspace():
            if started:
                fields.append("".join(field))
                field = []
                started = False
        else:
            field.append(char)
            started = True
    if quote or escaped:
        return None
    return fields + (["".join(field)] if started else [])


def _split_list(value):
    """Split a comma-separated Gunicorn option."""
    return [item.strip() for item in (value or "").split(",") if item.strip()]

