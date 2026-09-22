"""Parse Python interpreter and framework launch commands."""

import os

from .frameworks import PARSERS, parse_django
from .model import Launch, PathConfig, TARGET_RUNNABLE_MODULE, TARGET_SCRIPT


INTERPRETER_FLAGS = set("bBdEhiIOPqRsStuvVx?")
NON_APPLICATION_MODULES = {
    "ensurepip", "http.server", "idlelib", "pip", "pydoc", "pytest", "unittest", "venv",
}
DIRECT_LAUNCHERS = set(PARSERS) - {"fastapi"}


def command_name(path):
    """Return a normalized executable or script name."""
    return os.path.splitext(os.path.basename(path or ""))[0].lower()


def parse_python_launch(executable, args, env):
    """Parse a Python process launch using OBI precedence."""
    env = env or {}
    command = command_name(executable)
    if _is_interpreter(command):
        if args and command_name(args[0]) in DIRECT_LAUNCHERS:
            return _parse_launcher(command_name(args[0]), args[1:], env)
        return _parse_interpreter(args, env)
    if command in PARSERS:
        return _parse_launcher(command, args, env)
    return Launch()


def _is_interpreter(command):
    """Recognize CPython and PyPy executable names."""
    return command.startswith("python") or command.startswith("pypy")


def _parse_launcher(command, args, env):
    """Dispatch a framework launch parser."""
    launch = PARSERS[command](args, env)
    launch.source = command
    return launch


def _parse_interpreter(args, env):
    """Parse Python interpreter flags and its application target."""
    config = PathConfig()
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            if index + 1 < len(args):
                return _apply_path_config(_script_launch(args[index + 1], args[index + 2:], env), config)
            return Launch()
        if arg == "-":
            return Launch()
        if arg == "--check-hash-based-pycs":
            index += 2
            continue
        if arg.startswith("--"):
            index += 1
            continue
        if arg.startswith("-"):
            launch, done, index = _parse_short_options(arg[1:], args, index, env, config)
            if done:
                return _apply_path_config(launch, config)
        else:
            return _apply_path_config(_script_launch(arg, args[index + 1:], env), config)
        index += 1
    return Launch()


def _parse_short_options(options, args, index, env, config):
    """Parse a cluster of Python interpreter short options."""
    for offset, option in enumerate(options):
        if option == "E":
            config.ignore_environment = True
        elif option == "I":
            config.ignore_environment = True
            config.safe_path = True
        elif option == "P":
            config.safe_path = True
        elif option == "c":
            return Launch(), True, index
        elif option == "m":
            module = options[offset + 1:]
            if not module:
                index += 1
                if index >= len(args):
                    return Launch(), True, index
                module = args[index]
            return _module_launch(module, args[index + 1:], env), True, index
        elif option in {"W", "X"}:
            if offset + 1 == len(options):
                index += 1
                if index >= len(args):
                    return Launch(), True, index
            return Launch(), False, index
        elif option not in INTERPRETER_FLAGS:
            return Launch(), True, index
    return Launch(), False, index


def _module_launch(module, args, env):
    """Build a launch from a runnable Python module."""
    if module in PARSERS:
        return _parse_launcher(module, args, env)
    if module in NON_APPLICATION_MODULES:
        return Launch()
    return Launch(target=module, target_kind=TARGET_RUNNABLE_MODULE, source="python module")


def _script_launch(script, args, env):
    """Build a launch from a Python script path."""
    command = command_name(script)
    if command in PARSERS:
        return _parse_launcher(command, args, env)
    if command == "manage":
        launch = parse_django(args, env)
        launch.source = "django manage.py"
        if launch.target:
            launch.script_dir = os.path.dirname(script)
        else:
            launch.target = script
            launch.target_kind = TARGET_SCRIPT
        return launch
    if script == "-":
        return Launch()
    return Launch(target=script, target_kind=TARGET_SCRIPT, source="python script")


def _apply_path_config(launch, config):
    """Apply interpreter path flags to a meaningful launch."""
    meaningful = launch.target or launch.fallback_name or launch.app_dir or launch.search_paths
    meaningful = meaningful or launch.fastapi_auto or launch.flask_auto
    if meaningful:
        launch.path_config = config
    return launch
