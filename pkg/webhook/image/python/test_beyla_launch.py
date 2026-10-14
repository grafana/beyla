"""Tests for OBI-compatible Python launch parsing."""

import unittest

from _beyla_otel.launch import parse_python_launch


class TestPythonLaunch(unittest.TestCase):
    def test_supported_launchers(self):
        cases = [
            ("gunicorn", ["-w", "4", "orders.wsgi:application"], {}, "orders.wsgi:application", "module"),
            ("uvicorn", ["orders.api:app", "--port", "8000"], {}, "orders.api:app", "module"),
            ("hypercorn", ["--bind", ":8000", "orders.asgi:app"], {}, "orders.asgi:app", "module"),
            ("daphne", ["-b", "0.0.0.0", "orders.asgi:application"], {}, "orders.asgi:application", "module"),
            ("uwsgi", ["--module", "orders.wsgi:application"], {}, "orders.wsgi:application", "module"),
            ("waitress-serve", ["orders.wsgi:application"], {}, "orders.wsgi:application", "module"),
            ("flask", ["--app", "orders.web:create_app", "run"], {}, "orders.web:create_app", "module"),
            ("fastapi", ["run", "src/orders/main.py"], {}, "src/orders/main.py", "file"),
            ("django-admin", ["runserver", "--settings=orders.settings"], {}, "orders.settings", "module"),
            ("celery", ["-A", "orders.tasks", "worker"], {}, "orders.tasks", "module"),
        ]
        for executable, args, env, target, kind in cases:
            with self.subTest(executable=executable):
                launch = parse_python_launch(executable, args, env)
                self.assertEqual((target, kind), (launch.target, launch.target_kind))

    def test_generic_script_and_module(self):
        script = parse_python_launch("python3.14", ["/srv/orders.py"], {})
        module = parse_python_launch("python", ["-m", "company.orders"], {})

        self.assertEqual(("/srv/orders.py", "script"), (script.target, script.target_kind))
        self.assertEqual(("company.orders", "runnable_module"), (module.target, module.target_kind))

    def test_framework_named_python_files_remain_scripts(self):
        for filename in ("celery.py", "flask.py", "django.py"):
            script = "/srv/" + filename
            for args in ([script], ["-I", script], ["--", script]):
                with self.subTest(args=args):
                    launch = parse_python_launch("python", args, {})
                    self.assertEqual((script, "script"), (launch.target, launch.target_kind))
                    self.assertEqual("python script", launch.source)

    def test_extensionless_framework_console_script_uses_framework_parser(self):
        launch = parse_python_launch(
            "python",
            ["/venv/bin/gunicorn", "-w", "4", "orders.wsgi:application"],
            {},
        )

        self.assertEqual(("orders.wsgi:application", "module"), (launch.target, launch.target_kind))
        self.assertEqual("gunicorn", launch.source)

    def test_framework_environment(self):
        uvicorn = parse_python_launch(
            "uvicorn", [], {"UVICORN_APP": "orders.api:app", "UVICORN_APP_DIR": "/srv"}
        )
        celery = parse_python_launch("celery", ["worker"], {"CELERY_APP": "orders.tasks"})

        self.assertEqual("orders.api:app", uvicorn.target)
        self.assertEqual(["/srv"], uvicorn.search_paths)
        self.assertEqual("orders.tasks", celery.target)

    def test_gunicorn_environment_and_cli_precedence(self):
        launch = parse_python_launch(
            "gunicorn",
            ["--chdir", "/srv/orders", "--name", "cli-name", "orders.wsgi:application"],
            {"GUNICORN_CMD_ARGS": "--chdir '/srv/default app' --pythonpath=/libs,/shared --name env-name"},
        )

        self.assertEqual("/srv/orders", launch.app_dir)
        self.assertEqual(["/shared", "/libs", "/srv/orders"], launch.search_paths)
        self.assertEqual("cli-name", launch.fallback_name)

    def test_interpreter_isolation_flags(self):
        launch = parse_python_launch("python", ["-IPmcompany.orders"], {})

        self.assertTrue(launch.path_config.ignore_environment)
        self.assertTrue(launch.path_config.safe_path)

    def test_manage_py_uses_settings_and_script_directory(self):
        launch = parse_python_launch(
            "python", ["/srv/orders/manage.py", "runserver", "--settings", "orders.settings"], {}
        )

        self.assertEqual("orders.settings", launch.target)
        self.assertEqual("/srv/orders", launch.script_dir)

    def test_unknown_options_fail_closed(self):
        for executable, args in (
            ("uvicorn", ["--future-option", "value", "orders.api:app"]),
            ("hypercorn", ["--future-option", "value", "orders.asgi:app"]),
            ("daphne", ["--future-option", "value", "orders.asgi:app"]),
            ("waitress-serve", ["--future-option", "value", "orders.wsgi:application"]),
            ("fastapi", ["run", "--future-option", "value", "orders.py"]),
        ):
            with self.subTest(executable=executable):
                self.assertEqual("", parse_python_launch(executable, args, {}).target)

    def test_non_application_modules_are_ignored(self):
        for module in ("http.server", "pip", "pytest", "unittest"):
            with self.subTest(module=module):
                self.assertEqual("", parse_python_launch("python", ["-m", module], {}).target)


if __name__ == "__main__":
    unittest.main()
