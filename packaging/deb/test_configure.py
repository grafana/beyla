#!/usr/bin/env python3
"""Fast tests for the install-time configuration helper."""

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("configure.py")
SPEC = importlib.util.spec_from_file_location("beyla_configure", MODULE_PATH)
CONFIGURE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CONFIGURE)
VALIDATOR_SPEC = importlib.util.spec_from_file_location(
    "beyla_validate", Path(__file__).with_name("validate-alloy.py")
)
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader is not None
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)


def inputs(root: Path, mode: str = "sdk") -> dict[str, str]:
    return {
        "BEYLA_PACKAGE_ROOT": str(root),
        "BEYLA_SDK_MODE": mode,
        "BEYLA_SDK_SERVICES": "demo.service" if mode == "sdk" else "",
        "BEYLA_OPEN_PORTS": "18080",
        "GRAFANA_CLOUD_OTLP_ENDPOINT": "https://otlp.example/otlp",
        "GRAFANA_CLOUD_OTLP_TENANT_ID": "trace-tenant",
        "GRAFANA_CLOUD_OTLP_TOKEN": "trace-secret",
        "GRAFANA_CLOUD_METRICS_ENDPOINT": "https://metrics.example/api/v1/push",
        "GRAFANA_CLOUD_METRICS_TENANT_ID": "metrics-tenant",
        "GRAFANA_CLOUD_METRICS_TOKEN": "metrics-secret",
        "GRAFANA_CLOUD_PROFILES_ENDPOINT": "https://profiles.example/pyroscope",
        "GRAFANA_CLOUD_PROFILES_TENANT_ID": "profiles-tenant",
        "GRAFANA_CLOUD_PROFILES_TOKEN": "profiles-secret",
        "BEYLA_FLEET_ENABLED": "false",
    }


class ConfigureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        CONFIGURE.ROOT = self.root
        CONFIGURE.ETC = self.root / "etc/grafana/beyla-sdk"
        CONFIGURE.STATE = self.root / "var/lib/grafana-beyla-sdk"
        CONFIGURE.DROPINS = self.root / "etc/systemd/system"
        CONFIGURE.ETC.mkdir(mode=0o755, parents=True)
        (CONFIGURE.ETC / "config.alloy").write_text(
            MODULE_PATH.with_name("alloy-config.alloy").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        unit = self.root / "usr/lib/systemd/system/demo.service"
        unit.parent.mkdir(parents=True)
        unit.write_text("[Service]\nExecStart=/usr/bin/demo\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_empty_package_root_uses_absolute_installed_paths(self) -> None:
        with mock.patch.dict(os.environ, {"BEYLA_PACKAGE_ROOT": ""}, clear=True):
            self.assertEqual(CONFIGURE.package_root(), Path("/"))
            self.assertEqual(VALIDATOR.package_root(), Path("/"))

    def test_sdk_mode_writes_root_secrets_and_only_targeted_dropin(self) -> None:
        with mock.patch.dict(os.environ, inputs(self.root), clear=True):
            CONFIGURE.main()
        etc = CONFIGURE.ETC
        alloy_env = etc / "alloy.env"
        sdk_env = etc / "sdk.env"
        dropin = self.root / "etc/systemd/system/demo.service.d/90-grafana-beyla-sdk.conf"
        self.assertEqual(alloy_env.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sdk_env.stat().st_mode & 0o777, 0o600)
        self.assertIn('CONFIG_FILE="' + str(etc / "config.alloy") + '"', alloy_env.read_text())
        self.assertIn("trace-secret", alloy_env.read_text())
        self.assertIn("http://127.0.0.1:14318", sdk_env.read_text())
        self.assertNotIn("trace-secret", sdk_env.read_text())
        self.assertNotIn("/etc/ld.so.preload", dropin.read_text())
        self.assertIn("LD_PRELOAD", sdk_env.read_text())
        self.assertIn("traces = []", (etc / "config.alloy").read_text())
        self.assertTrue(dropin.exists())
        self.assertFalse((self.root / "etc/ld.so.preload").exists())

        # Re-running the install configurator is idempotent and preserves any
        # edits made to root-only credentials.
        original = alloy_env.read_text()
        alloy_env.write_text(original + "# retained local change\n")
        with mock.patch.dict(os.environ, inputs(self.root), clear=True):
            CONFIGURE.main()
        self.assertIn("# retained local change", alloy_env.read_text())

    def test_beyla_only_does_not_write_application_dropins(self) -> None:
        with mock.patch.dict(os.environ, inputs(self.root, mode="beyla-only"), clear=True):
            CONFIGURE.main()
        self.assertIn(
            "traces = [otelcol.exporter.otlphttp.cloud.input]",
            (CONFIGURE.ETC / "config.alloy").read_text(),
        )
        self.assertEqual((self.root / "var/lib/grafana-beyla-sdk/mode").read_text().strip(), "beyla-only")
        self.assertFalse((self.root / "etc/systemd/system/demo.service.d").exists())
        self.assertFalse((self.root / "etc/grafana/beyla-sdk/sdk.env").exists())

    def test_fleet_is_absent_by_default(self) -> None:
        with mock.patch.dict(os.environ, inputs(self.root), clear=True):
            CONFIGURE.main()
        config = (CONFIGURE.ETC / "config.alloy").read_text()
        env = (CONFIGURE.ETC / "alloy.env").read_text()
        self.assertNotIn("remotecfg", config)
        self.assertNotIn("FLEET", env)

    def test_enabled_fleet_adds_root_block_and_root_only_inputs(self) -> None:
        env = inputs(self.root)
        env.update(
            {
                "BEYLA_FLEET_ENABLED": "true",
                "GRAFANA_CLOUD_FLEET_URL": "https://fleet.example/api/v1/remotecfg",
                # Opaque IDs are not parsed as URLs or constrained to a numeric tenant.
                "GRAFANA_CLOUD_FLEET_INSTANCE_ID": "opaque / instance:01",
            }
        )
        with mock.patch.dict(os.environ, env, clear=True):
            CONFIGURE.main()
        config = (CONFIGURE.ETC / "config.alloy").read_text()
        alloy_env = CONFIGURE.ETC / "alloy.env"
        self.assertIn("remotecfg {", config)
        self.assertIn('url = sys.env("GRAFANA_CLOUD_FLEET_URL")', config)
        self.assertIn('username = sys.env("GRAFANA_CLOUD_FLEET_INSTANCE_ID")', config)
        self.assertIn('password = sys.env("GRAFANA_CLOUD_OTLP_TOKEN")', config)
        self.assertNotIn('id = sys.env("GRAFANA_CLOUD_FLEET_INSTANCE_ID")', config)
        self.assertIn('GRAFANA_CLOUD_FLEET_URL="https://fleet.example/api/v1/remotecfg"', alloy_env.read_text())
        self.assertIn('GRAFANA_CLOUD_FLEET_INSTANCE_ID="opaque / instance:01"', alloy_env.read_text())
        self.assertEqual(alloy_env.stat().st_mode & 0o777, 0o600)

    def test_fleet_fields_are_required_only_when_enabled(self) -> None:
        for missing_name in ("GRAFANA_CLOUD_FLEET_URL", "GRAFANA_CLOUD_FLEET_INSTANCE_ID"):
            env = inputs(self.root)
            env["BEYLA_FLEET_ENABLED"] = "true"
            env["GRAFANA_CLOUD_FLEET_URL"] = "https://fleet.example/api/v1/remotecfg"
            env["GRAFANA_CLOUD_FLEET_INSTANCE_ID"] = "opaque-id"
            env.pop(missing_name)
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(ValueError, "missing or invalid"):
                    CONFIGURE.main()
            self.assertFalse((CONFIGURE.ETC / "alloy.env").exists())
            env[missing_name] = ""
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaisesRegex(ValueError, "missing or invalid"):
                    CONFIGURE.main()

    def test_fleet_injection_is_idempotent(self) -> None:
        env = inputs(self.root)
        env.update(
            {
                "BEYLA_FLEET_ENABLED": "true",
                "GRAFANA_CLOUD_FLEET_URL": "https://fleet.example/api/v1/remotecfg",
                "GRAFANA_CLOUD_FLEET_INSTANCE_ID": "opaque-id",
            }
        )
        with mock.patch.dict(os.environ, env, clear=True):
            CONFIGURE.main()
            CONFIGURE.configure_mode("sdk", fleet_enabled=True)
        config = (CONFIGURE.ETC / "config.alloy").read_text()
        self.assertEqual(config.count("remotecfg {"), 1)

    def test_enabled_to_disabled_rerun_preserves_install_time_fleet_state(self) -> None:
        enabled = inputs(self.root)
        enabled.update(
            {
                "BEYLA_FLEET_ENABLED": "true",
                "GRAFANA_CLOUD_FLEET_URL": "https://fleet.example/api/v1/remotecfg",
                "GRAFANA_CLOUD_FLEET_INSTANCE_ID": "opaque-id",
            }
        )
        with mock.patch.dict(os.environ, enabled, clear=True):
            CONFIGURE.main()
        config_path = CONFIGURE.ETC / "config.alloy"
        env_path = CONFIGURE.ETC / "alloy.env"
        config_before = config_path.read_text()
        env_before = env_path.read_text()

        disabled = inputs(self.root)
        disabled["BEYLA_FLEET_ENABLED"] = "false"
        # Even if debconf was changed after installation, the existing config
        # and matching root-only environment stay as the install-time choice.
        with mock.patch.dict(os.environ, disabled, clear=True):
            CONFIGURE.main()
        self.assertEqual(config_path.read_text(), config_before)
        self.assertEqual(env_path.read_text(), env_before)
        self.assertIn("remotecfg {", config_path.read_text())
        self.assertIn("GRAFANA_CLOUD_FLEET_URL=", env_path.read_text())

    def test_rerun_does_not_upgrade_disabled_fleet_state_from_ambient_values(self) -> None:
        disabled = inputs(self.root)
        with mock.patch.dict(os.environ, disabled, clear=True):
            CONFIGURE.main()
        config_path = CONFIGURE.ETC / "config.alloy"
        env_path = CONFIGURE.ETC / "alloy.env"
        config_before = config_path.read_text()
        env_before = env_path.read_text()
        rerun = inputs(self.root)
        rerun.update(
            {
                "BEYLA_FLEET_ENABLED": "true",
                "GRAFANA_CLOUD_FLEET_URL": "https://ambient.example/remotecfg",
                "GRAFANA_CLOUD_FLEET_INSTANCE_ID": "ambient-id",
            }
        )
        with mock.patch.dict(os.environ, rerun, clear=True):
            CONFIGURE.main()
        self.assertEqual(config_path.read_text(), config_before)
        self.assertEqual(env_path.read_text(), env_before)
        self.assertNotIn("remotecfg", config_path.read_text())
        self.assertNotIn("FLEET", env_path.read_text())

    def test_refuses_foreign_dropin_before_writing_credentials(self) -> None:
        foreign = self.root / "etc/systemd/system/demo.service.d/90-grafana-beyla-sdk.conf"
        foreign.parent.mkdir(parents=True)
        foreign.write_text("[Service]\nEnvironment=LD_PRELOAD=/other.so\n", encoding="utf-8")
        with mock.patch.dict(os.environ, inputs(self.root), clear=True):
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                CONFIGURE.main()
        self.assertFalse((self.root / "etc/grafana/beyla-sdk/alloy.env").exists())

    def test_refuses_invalid_unit_and_missing_service(self) -> None:
        for service in ("../../outside.service", "missing.service"):
            env = inputs(self.root)
            env["BEYLA_SDK_SERVICES"] = service
            with mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(ValueError):
                    CONFIGURE.main()
        self.assertFalse((self.root / "etc/grafana/beyla-sdk/alloy.env").exists())

    def test_validator_reads_quoted_env_without_logging_credentials(self) -> None:
        envfile = self.root / "alloy.env"
        envfile.write_text('TOKEN="secret with spaces"\nQUOTE="say \\\"hi\\\""\n', encoding="utf-8")
        parsed = VALIDATOR.read_environment(envfile)
        self.assertEqual(parsed["TOKEN"], "secret with spaces")
        self.assertEqual(parsed["QUOTE"], 'say "hi"')


if __name__ == "__main__":
    unittest.main()
