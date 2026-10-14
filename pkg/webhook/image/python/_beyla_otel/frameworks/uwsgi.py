"""uWSGI launch parsing."""

from ..model import Launch, TARGET_FILE, TARGET_MODULE


UWSGI_MODULE_OPTIONS = {"-w", "--module", "--wsgi"}
UWSGI_FILE_OPTIONS = {"--wsgi-file", "--file"}
UWSGI_PATH_OPTIONS = {"--pythonpath", "--python-path", "--pp"}
UWSGI_TRACKED_OPTIONS = UWSGI_MODULE_OPTIONS | UWSGI_FILE_OPTIONS | UWSGI_PATH_OPTIONS
UWSGI_VALUE_OPTIONS = UWSGI_TRACKED_OPTIONS | {
    "--http", "--http-socket", "--https", "--socket", "--uwsgi-socket",
}
UWSGI_FLAG_OPTIONS = {"-M", "--master"}


def parse_uwsgi(args, env):
    """Parse a uWSGI launch."""
    module = ""
    file_target = ""
    paths = []
    index = 0
    while index < len(args):
        name, separator, value = _uwsgi_option(args[index])
        if name in UWSGI_VALUE_OPTIONS:
            if not separator:
                index += 1
                if index == len(args):
                    return Launch()
                value = args[index]
            if name in UWSGI_MODULE_OPTIONS:
                module = value
            elif name in UWSGI_FILE_OPTIONS:
                file_target = value
            elif name in UWSGI_PATH_OPTIONS:
                paths.append(value)
        elif name not in UWSGI_FLAG_OPTIONS and _tracked_option_follows(args, index):
            return Launch()
        index += 1
    if module and file_target:
        return Launch()
    if module:
        return Launch(target=module, target_kind=TARGET_MODULE, search_paths=list(reversed(paths)) + ["."])
    if file_target:
        return Launch(target=file_target, target_kind=TARGET_FILE, search_paths=list(reversed(paths)) + ["."])
    return Launch(search_paths=list(reversed(paths)) + ["."])


def _uwsgi_option(arg):
    """Split a uWSGI option into its name and optional attached value."""
    name, separator, value = arg.partition("=")
    if arg.startswith("-w") and not arg.startswith("--") and len(arg) > 2:
        return "-w", "=", arg[2:].lstrip("=")
    return name, separator, value


def _tracked_option_follows(args, index):
    """Detect an ambiguous tracked option after an option of unknown arity."""
    if not args[index].startswith("-") or "=" in args[index] or index + 1 == len(args):
        return False
    return _uwsgi_option(args[index + 1])[0] in UWSGI_TRACKED_OPTIONS
