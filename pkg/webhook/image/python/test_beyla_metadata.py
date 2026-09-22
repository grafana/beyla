"""Tests for Python application service metadata detection."""

import os
import tempfile
import unittest
from pathlib import Path

from _beyla_otel.metadata import detect_service_metadata


class Project:
    def __init__(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def close(self):
        self.tempdir.cleanup()

    def write(self, path, contents=""):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
        return target


class TestServiceMetadata(unittest.TestCase):
    def setUp(self):
        self.project = Project()

    def tearDown(self):
        self.project.close()

    def detect(self, executable, args, env=None, cwd=None):
        return detect_service_metadata(
            cmdline=(executable, args),
            cwd=str(cwd or self.project.root),
            env=env or {},
        )

    def test_pep_621_metadata_precedes_target(self):
        self.project.write("orders/wsgi.py")
        self.project.write(
            "pyproject.toml",
            "[project]\nname = 'Orders-Service'\nversion = '1.2.3'\n",
        )

        metadata = self.detect("gunicorn", ["orders.wsgi:application"])

        self.assertEqual("Orders-Service", metadata.name)
        self.assertEqual("1.2.3", metadata.version)
        self.assertEqual("pyproject.toml [project]", metadata.name_source)

    def test_pep_621_precedes_poetry(self):
        self.project.write("orders.py")
        self.project.write(
            "pyproject.toml",
            "[project]\nname = 'pep-orders'\nversion = '2.0'\n"
            "[tool.poetry]\nname = 'poetry-orders'\nversion = '1.0'\n",
        )

        metadata = self.detect("python", ["orders.py"])

        self.assertEqual(("pep-orders", "2.0"), (metadata.name, metadata.version))

    def test_poetry_metadata(self):
        self.project.write("orders.py")
        self.project.write(
            "pyproject.toml", "[tool.poetry]\nname = 'poetry-orders'\nversion = '3.1'\n"
        )

        metadata = self.detect("python", ["orders.py"])

        self.assertEqual(("poetry-orders", "3.1"), (metadata.name, metadata.version))

    def test_setup_cfg_metadata(self):
        self.project.write("orders.py")
        self.project.write("pyproject.toml", "[build-system]\nrequires = []\n")
        self.project.write("setup.cfg", "[metadata]\nname = setup-orders\nversion = 4.0\n")

        metadata = self.detect("python", ["orders.py"])

        self.assertEqual(("setup-orders", "4.0"), (metadata.name, metadata.version))

    def test_dynamic_version_is_ignored(self):
        self.project.write("orders.py")
        self.project.write(
            "pyproject.toml",
            "[project]\nname = 'orders'\nversion = '9.9'\ndynamic = ['version']\n",
        )

        metadata = self.detect("python", ["orders.py"])

        self.assertEqual("orders", metadata.name)
        self.assertEqual("", metadata.version)

    def test_multiline_dynamic_version_is_conservatively_ignored(self):
        self.project.write("orders.py")
        self.project.write(
            "pyproject.toml",
            "[project]\nname = 'orders'\nversion = '9.9'\ndynamic = [\n  'version',\n]\n",
        )

        metadata = self.detect("python", ["orders.py"])

        self.assertEqual("orders", metadata.name)
        self.assertEqual("", metadata.version)

    def test_invalid_project_name_falls_back_to_target(self):
        self.project.write("company/orders/api.py")
        self.project.write("pyproject.toml", "[project]\nname = '../outside'\n")

        metadata = self.detect("uvicorn", ["company.orders.api:app"])

        self.assertEqual("orders", metadata.name)

    def test_metadata_requires_a_resolved_target(self):
        self.project.write("pyproject.toml", "[project]\nname = 'wrong-project'\nversion = '9.9'\n")

        metadata = self.detect("python", ["orders.py"])

        self.assertEqual("orders", metadata.name)
        self.assertEqual("", metadata.version)

    def test_generic_script_uses_application_directory(self):
        application = self.project.root / "python-travel-agent"
        self.project.write("python-travel-agent/server.py")

        metadata = self.detect("python", ["server.py"], cwd=application)

        self.assertEqual("python-travel-agent", metadata.name)
        self.assertEqual("application directory", metadata.name_source)

    def test_application_directory_does_not_walk_above_cwd(self):
        application = self.project.root / "app"
        self.project.write("app/server.py")

        metadata = self.detect("python", ["server.py"], cwd=application)

        self.assertEqual("", metadata.name)

    def test_nearest_project_is_a_boundary(self):
        self.project.write("pyproject.toml", "[project]\nname = 'workspace'\n")
        service = self.project.root / "services/orders"
        self.project.write("services/orders/pyproject.toml", "[build-system]\nrequires = []\n")
        self.project.write("services/orders/orders/api.py")

        metadata = self.detect("uvicorn", ["orders.api:app"], cwd=service)

        self.assertEqual("orders", metadata.name)

    def test_fastapi_automatic_entrypoint(self):
        self.project.write("backend/main.py")
        self.project.write(
            "pyproject.toml",
            "[project]\nname = 'fast-orders'\nversion = '5.0'\n"
            "[tool.fastapi]\nentrypoint = 'backend.main:app'\n",
        )

        metadata = self.detect("fastapi", ["run"])

        self.assertEqual(("fast-orders", "5.0"), (metadata.name, metadata.version))

    def test_flask_automatic_application(self):
        self.project.write("app.py")
        self.project.write("pyproject.toml", "[project]\nname = 'flask-orders'\nversion = '1.0'\n")

        metadata = self.detect("flask", ["run"])

        self.assertEqual(("flask-orders", "1.0"), (metadata.name, metadata.version))

    def test_gunicorn_name_is_the_final_fallback(self):
        metadata = self.detect("gunicorn", ["--name", "orders-worker", "-b", ":8080"])

        self.assertEqual("orders-worker", metadata.name)

    def test_pythonpath_resolves_application_project(self):
        library = self.project.root / "libs"
        self.project.write("libs/orders.py")
        self.project.write("libs/pyproject.toml", "[project]\nname = 'path-orders'\nversion = '2'\n")

        metadata = self.detect("python", ["-P", "-m", "orders"], {"PYTHONPATH": str(library)})

        self.assertEqual(("path-orders", "2"), (metadata.name, metadata.version))

    def test_isolated_mode_ignores_pythonpath(self):
        library = self.project.root / "libs"
        self.project.write("libs/orders.py")
        self.project.write("libs/pyproject.toml", "[project]\nname = 'path-orders'\n")

        metadata = self.detect("python", ["-I", "-m", "orders"], {"PYTHONPATH": str(library)})

        self.assertEqual("orders", metadata.name)


if __name__ == "__main__":
    unittest.main()
