"""Resolve Python service metadata without importing application code."""

import json
import os
import sys

from .frameworks import classify_target, clean_value, target_name, target_reference
from .launch import parse_python_launch
from .log import warning
from .model import (
    Launch,
    ProjectMetadata,
    PyProject,
    TARGET_DOTTED_REFERENCE,
    TARGET_FILE,
    TARGET_MODULE,
    TARGET_RUNNABLE_MODULE,
    TARGET_SCRIPT,
)


MAX_PROJECT_FILE_BYTES = 2 * 1024 * 1024


def detect_service_metadata(cmdline=None, cwd=None, env=None):
    """Resolve service name and version using OBI precedence."""
    env = os.environ if env is None else env
    executable, args = cmdline or read_commandline()
    cwd = _working_directory(cwd)
    if not executable or not cwd:
        return ProjectMetadata()
    launch = parse_python_launch(executable, args, env)
    _resolve_fastapi_entrypoint(cwd, launch)
    metadata, target_path = _metadata_for_launch(cwd, launch, env)
    if not metadata.name:
        metadata.name = target_name(launch.target)
        if metadata.name:
            metadata.name_source = "{} target".format(launch.source or "python launch")
    if not metadata.name:
        metadata.name = clean_value(launch.fallback_name)
        if metadata.name:
            metadata.name_source = "{} fallback".format(launch.source or "python launch")
    if not metadata.name and launch.target_kind == TARGET_SCRIPT:
        metadata.name = _application_directory_name(target_path, cwd)
        if metadata.name:
            metadata.name_source = "application directory"
    return metadata


def _resolve_fastapi_entrypoint(cwd, launch):
    """Apply FastAPI automatic entrypoint configuration to a launch."""
    if not launch.fastapi_auto:
        return
    entrypoint, config_dir = find_fastapi_entrypoint(cwd)
    if entrypoint:
        launch.target = entrypoint
        launch.target_kind = classify_target(entrypoint)
        launch.search_paths.insert(0, config_dir)


def _metadata_for_launch(cwd, launch, env):
    """Resolve a launch target and read its project metadata."""
    target_path, resolved_target = resolve_target_path(cwd, launch, env)
    if launch.flask_auto:
        target_path, resolved_target = resolve_flask_target(cwd, launch, env)
    if target_path:
        launch.target = resolved_target
        return find_project_metadata(target_path), target_path
    if launch.target_kind == TARGET_DOTTED_REFERENCE:
        launch.target = ""
    return ProjectMetadata(), ""


def _application_directory_name(target_path, cwd):
    """Find a non-generic script directory without walking above the working directory."""
    if not target_path:
        return ""
    directory = os.path.dirname(os.path.realpath(target_path))
    boundary = os.path.realpath(cwd)
    try:
        if os.path.commonpath((directory, boundary)) != boundary:
            return ""
    except ValueError:
        return ""
    while True:
        name = target_name(os.path.basename(directory))
        if name:
            return name
        if directory == boundary:
            return ""
        directory = os.path.dirname(directory)


def read_commandline():
    """Read the original process command line with a portable fallback."""
    try:
        with open("/proc/self/cmdline", "rb") as command_file:
            values = [os.fsdecode(value) for value in command_file.read().split(b"\0") if value]
        if values:
            return values[0], values[1:]
    except OSError as error:
        warning("could not read /proc/self/cmdline: {}".format(error))
    return sys.executable, list(sys.argv)


def _working_directory(value):
    """Return an explicit or current working directory."""
    if value is not None:
        return value
    try:
        return os.getcwd()
    except OSError as error:
        warning("could not read the working directory: {}".format(error))
        return ""


def resolve_flask_target(cwd, launch, env):
    """Probe Flask's default wsgi and app modules."""
    for target in ("wsgi", "app"):
        candidate = Launch(target=target, target_kind=TARGET_MODULE, search_paths=["."])
        candidate.path_config = launch.path_config
        resolved = resolve_target_path(cwd, candidate, env)
        if resolved[0]:
            launch.target = target
            launch.target_kind = TARGET_MODULE
            launch.source = "flask automatic application"
            return resolved
    return "", ""


def resolve_target_path(cwd, launch, env):
    """Resolve a launch target to an application file."""
    if launch.target_kind == TARGET_SCRIPT:
        if not launch.target:
            return "", ""
        candidates = ((launch.target, launch.target), (os.path.join(launch.target, "__main__.py"), launch.target))
        return _resolve_candidates([cwd], candidates)

    target = target_reference(launch.target)
    if not target:
        return "", ""
    roots = _target_search_roots(cwd, launch, env)
    if launch.target_kind == TARGET_FILE:
        candidates = [(target, target)]
        if not os.path.splitext(target)[1]:
            candidates.extend(((target + ".py", target), (os.path.join(target, "__init__.py"), target)))
        return _resolve_candidates(roots, candidates)
    if launch.target_kind == TARGET_MODULE:
        resolved = _resolve_module(roots, target)
        return (resolved[0], target) if resolved[3] and resolved[0] else ("", "")
    if launch.target_kind == TARGET_RUNNABLE_MODULE:
        return _resolve_runnable_module(roots, target)
    if launch.target_kind == TARGET_DOTTED_REFERENCE:
        return _resolve_dotted_reference(roots, target)
    return "", ""


def _target_search_roots(cwd, launch, env):
    """Build Python target search roots in interpreter order."""
    config = launch.path_config
    safe_path = config.safe_path or (not config.ignore_environment and bool(env.get("PYTHONSAFEPATH")))
    python_path = "" if config.ignore_environment else env.get("PYTHONPATH", "")
    include_cwd = not safe_path or launch.target_kind == TARGET_FILE
    launcher_paths = list(launch.search_paths)
    if launch.script_dir:
        include_cwd = False
        if not safe_path:
            launcher_paths.append(launch.script_dir)
    roots = []
    for path in launcher_paths:
        _append_path(roots, cwd, path)
    if include_cwd:
        _append_path(roots, cwd, cwd)
    for path in python_path.split(os.pathsep) if python_path else []:
        _append_path(roots, cwd, path or cwd)
    return roots


def _append_path(paths, cwd, path):
    """Append a unique absolute process path."""
    if not path:
        return
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    path = os.path.normpath(path)
    if path not in paths:
        paths.append(path)


def _resolve_candidates(roots, candidates):
    """Return the first regular target candidate."""
    for root in roots:
        for path, target in candidates:
            candidate = path if os.path.isabs(path) else os.path.join(root, path)
            if os.path.isfile(candidate):
                return os.path.realpath(candidate), target
    return "", ""


def _resolve_module(roots, module):
    """Resolve a Python module without importing it."""
    search_paths = list(roots)
    parts = module.split(".")
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        namespace_paths = []
        package_path = ""
        for root in search_paths:
            candidate_package = os.path.join(root, part)
            initializer = os.path.join(candidate_package, "__init__.py")
            if os.path.isfile(initializer):
                if last:
                    return os.path.realpath(initializer), [candidate_package], True, True
                package_path = candidate_package
                break
            module_file = os.path.join(root, part + ".py")
            if os.path.isfile(module_file):
                if not last:
                    return "", [], False, False
                return os.path.realpath(module_file), [], False, True
            if os.path.isdir(candidate_package) and candidate_package not in namespace_paths:
                namespace_paths.append(candidate_package)
        if package_path:
            search_paths = [package_path]
        elif not namespace_paths:
            return "", [], False, False
        elif last:
            return "", namespace_paths, True, True
        else:
            search_paths = namespace_paths
    return "", [], False, False


def _resolve_runnable_module(roots, module):
    """Resolve a module or package executable with python -m."""
    path, search_paths, package, found = _resolve_module(roots, module)
    if not found:
        return "", ""
    if not package:
        return path, module
    main_path, _, main_package, main_found = _resolve_module(search_paths, "__main__")
    if main_found and not main_package and main_path:
        return main_path, module
    return "", ""


def _resolve_dotted_reference(roots, target):
    """Resolve the longest module prefix of a dotted reference."""
    parts = target.split(".")
    for length in range(len(parts), 0, -1):
        module = ".".join(parts[:length])
        path, _, _, found = _resolve_module(roots, module)
        if found and path:
            return path, module
    return "", ""


def find_project_metadata(target_path):
    """Find the nearest recognized Python project metadata."""
    for directory in _parent_directories(os.path.dirname(target_path)):
        pyproject_path = os.path.join(directory, "pyproject.toml")
        pyproject, found, error = _read_pyproject(pyproject_path)
        if error:
            warning(error)
            return ProjectMetadata()
        pyproject_found = found
        if found and pyproject.recognized:
            return pyproject.metadata

        setup_path = os.path.join(directory, "setup.cfg")
        setup, found, error = _read_setup_config(setup_path)
        if error:
            warning(error)
            return ProjectMetadata()
        if found and setup.recognized:
            return setup.metadata
        if pyproject_found or found:
            break
    return ProjectMetadata()


def find_fastapi_entrypoint(cwd):
    """Find FastAPI's configured automatic entrypoint."""
    for directory in _parent_directories(cwd):
        pyproject_path = os.path.join(directory, "pyproject.toml")
        pyproject, found, error = _read_pyproject(pyproject_path)
        if error:
            warning(error)
            return "", ""
        pyproject_found = found
        if found:
            if pyproject.entrypoint:
                return pyproject.entrypoint, directory
            if pyproject.recognized or pyproject.fastapi_section:
                return "", ""

        setup, found, error = _read_setup_config(os.path.join(directory, "setup.cfg"))
        if error:
            warning(error)
            return "", ""
        if found and setup.recognized:
            return "", ""
        if pyproject_found or found:
            break
    return "", ""


def _parent_directories(start):
    """Yield a path and each parent through the filesystem root."""
    current = os.path.realpath(start)
    while current:
        yield current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent


def _read_metadata_file(path):
    """Read a bounded UTF-8 project metadata file."""
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return "", False, ""
    except OSError as error:
        return "", False, "reading {}: {}".format(path, error)
    if size > MAX_PROJECT_FILE_BYTES:
        return "", True, "reading {}: file exceeds {} bytes".format(path, MAX_PROJECT_FILE_BYTES)
    try:
        with open(path, "r", encoding="utf-8") as metadata_file:
            return metadata_file.read(), True, ""
    except (OSError, UnicodeError) as error:
        return "", True, "reading {}: {}".format(path, error)


def _read_pyproject(path):
    """Read the supported pyproject.toml metadata subset."""
    data, found, error = _read_metadata_file(path)
    if error or not found:
        return PyProject(), found, error
    try:
        return _parse_pyproject(data), True, ""
    except ValueError as parse_error:
        return PyProject(), True, "parsing {}: {}".format(path, parse_error)


def _parse_pyproject(data):
    """Parse common static metadata without a TOML dependency."""
    values = {"project": {}, "tool.poetry": {}, "tool.fastapi": {}}
    sections = set()
    section = ""
    for raw_line in data.splitlines():
        line = _strip_toml_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("["):
            if not line.endswith("]") or line.startswith("[["):
                section = ""
                continue
            section = line[1:-1].strip()
            if section in values:
                sections.add(section)
            continue
        if section not in values or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in {"name", "version", "entrypoint"}:
            values[section][key] = _parse_toml_string(value)
        elif section == "project" and key == "dynamic":
            values[section][key] = _parse_toml_array(value)

    result = PyProject(fastapi_section="tool.fastapi" in sections)
    result.entrypoint = clean_value(values["tool.fastapi"].get("entrypoint", ""))
    if "project" in sections:
        result.recognized = True
        project = values["project"]
        result.metadata = _pyproject_metadata(project, "pyproject.toml [project]")
    elif "tool.poetry" in sections:
        result.recognized = True
        result.metadata = _static_metadata(values["tool.poetry"], "pyproject.toml [tool.poetry]")
    return result


def _strip_toml_comment(line):
    """Remove a TOML comment outside a quoted string."""
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\" and quote == '"':
            escaped = True
        elif quote and char == quote:
            quote = ""
        elif not quote and char in {'"', "'"}:
            quote = char
        elif not quote and char == "#":
            return line[:index]
    return line


def _parse_toml_string(value):
    """Parse a common single-line TOML string."""
    value = value.strip()
    if len(value) < 2:
        return ""
    if value[0] == value[-1] == "'" and "'" not in value[1:-1]:
        return value[1:-1]
    if value[0] == value[-1] == '"':
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, str) else ""
        except (TypeError, ValueError):
            return ""
    return ""


def _parse_toml_array(value):
    """Parse a common single-line TOML string array."""
    value = value.strip()
    if not value.startswith("[") or not value.endswith("]"):
        return None
    items = []
    for item in value[1:-1].split(","):
        if not item.strip():
            continue
        parsed = _parse_toml_string(item)
        if not parsed:
            return None
        items.append(parsed)
    return items


def _pyproject_metadata(values, source):
    """Build PEP 621 metadata while honoring dynamic versions."""
    metadata = ProjectMetadata()
    metadata.name = _clean_project_name(values.get("name", ""))
    if metadata.name:
        metadata.name_source = source
    dynamic = values.get("dynamic", [])
    if dynamic is not None and "version" not in dynamic:
        metadata.version = clean_value(values.get("version", ""))
        if metadata.version:
            metadata.version_source = source
    return metadata


def _static_metadata(values, source):
    """Build static project metadata values."""
    metadata = ProjectMetadata(
        name=_clean_project_name(values.get("name", "")),
        version=clean_value(values.get("version", "")),
    )
    metadata.name_source = source if metadata.name else ""
    metadata.version_source = source if metadata.version else ""
    return metadata


def _read_setup_config(path):
    """Read setup.cfg static project metadata."""
    data, found, error = _read_metadata_file(path)
    if error or not found:
        return PyProject(), found, error
    result = PyProject()
    values = {}
    section = ""
    for line_number, raw_line in enumerate(data.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                return PyProject(), True, "parsing {}:{}: malformed section".format(path, line_number)
            section = line[1:-1].strip().lower()
            result.recognized = result.recognized or section == "metadata"
            continue
        if section != "metadata" or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key.lower() in {"name", "version"}:
            values[key.lower()] = value
    result.metadata.name = _clean_project_name(values.get("name", ""))
    version = values.get("version", "").strip()
    if not version.lower().startswith(("attr:", "file:")) and "%(" not in version:
        result.metadata.version = clean_value(version)
    source = "setup.cfg [metadata]"
    result.metadata.name_source = source if result.metadata.name else ""
    result.metadata.version_source = source if result.metadata.version else ""
    return result, True, ""


def _clean_project_name(value):
    """Validate an OBI-compatible Python project name."""
    value = clean_value(value)
    if not value or value[0] in "-_." or value[-1] in "-_.":
        return ""
    for char in value:
        if not char.isascii() or not (char.isalnum() or char in "-_."):
            return ""
    return value
