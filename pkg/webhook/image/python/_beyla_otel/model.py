"""Data shared by Python service metadata detectors."""

from dataclasses import dataclass, field


TARGET_NONE = "none"
TARGET_FILE = "file"
TARGET_SCRIPT = "script"
TARGET_MODULE = "module"
TARGET_RUNNABLE_MODULE = "runnable_module"
TARGET_DOTTED_REFERENCE = "dotted_reference"


@dataclass
class PathConfig:
    """Describe Python interpreter path controls."""

    ignore_environment: bool = False
    safe_path: bool = False


@dataclass
class Launch:
    """Describe a parsed Python application launch."""

    target: str = ""
    target_kind: str = TARGET_NONE
    app_dir: str = ""
    search_paths: list = field(default_factory=list)
    script_dir: str = ""
    fallback_name: str = ""
    fastapi_auto: bool = False
    flask_auto: bool = False
    path_config: PathConfig = field(default_factory=PathConfig)
    source: str = ""


@dataclass
class ProjectMetadata:
    """Hold service metadata read from a project file."""

    name: str = ""
    version: str = ""
    name_source: str = ""
    version_source: str = ""


@dataclass
class PyProject:
    """Hold the supported subset of pyproject.toml."""

    metadata: ProjectMetadata = field(default_factory=ProjectMetadata)
    entrypoint: str = ""
    recognized: bool = False
    fastapi_section: bool = False

