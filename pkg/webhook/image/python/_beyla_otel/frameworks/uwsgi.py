"""uWSGI launch parsing."""

from ..model import Launch, TARGET_FILE, TARGET_MODULE


def parse_uwsgi(args, env):
    """Parse a uWSGI launch."""
    module = ""
    file_target = ""
    paths = []
    index = 0
    while index < len(args):
        arg = args[index]
        name, separator, value = arg.partition("=")
        if arg.startswith("-w") and not arg.startswith("--") and len(arg) > 2:
            name, value, separator = "-w", arg[2:].lstrip("="), "="
        if name in {"-w", "--module", "--wsgi", "--wsgi-file", "--file", "--pythonpath", "--python-path", "--pp"}:
            if not separator:
                index += 1
                if index == len(args):
                    return Launch()
                value = args[index]
            if name in {"-w", "--module", "--wsgi"}:
                module = value
            elif name in {"--wsgi-file", "--file"}:
                file_target = value
            else:
                paths.append(value)
        index += 1
    if module and file_target:
        return Launch()
    if module:
        return Launch(target=module, target_kind=TARGET_MODULE, search_paths=list(reversed(paths)) + ["."])
    if file_target:
        return Launch(target=file_target, target_kind=TARGET_FILE, search_paths=list(reversed(paths)) + ["."])
    return Launch(search_paths=list(reversed(paths)) + ["."])

