#!/usr/bin/python3
"""Write root-only Alloy credentials and explicit opt-ins."""

import os
from pathlib import Path
import re
import tempfile


def package_root() -> Path:
    return Path(os.environ.get("BEYLA_PACKAGE_ROOT") or "/")


ROOT = package_root()
ETC = ROOT / "etc/beyla"
STATE = ROOT / "var/lib/beyla"
DROPINS = ROOT / "etc/systemd/system"
UNIT_NAME = re.compile(r"^[A-Za-z0-9_.@:-]+\.service$")


def required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError(f"missing or invalid required configuration value: {name}")
    return value


def systemd_value(value: str) -> str:
    if any(char in value for char in "\n\r\x00"):
        raise ValueError("newlines are not allowed in environment values")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def atomic_secret(path: Path, contents: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, temp_name = tempfile.mkstemp(prefix=".beyla-sdk-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, path)
        path.chmod(0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


FLEET_BEGIN = "// beyla fleet-managed begin"
FLEET_END = "// beyla fleet-managed end"


def fleet_block() -> str:
    return (
        f"{FLEET_BEGIN}\n"
        "remotecfg {\n"
        '  url = sys.env("GRAFANA_CLOUD_FLEET_URL")\n'
        "  basic_auth {\n"
        '    username = sys.env("GRAFANA_CLOUD_FLEET_INSTANCE_ID")\n'
        '    password = sys.env("GRAFANA_CLOUD_OTLP_TOKEN")\n'
        "  }\n"
        '  poll_frequency = "5m"\n'
        "}\n"
        f"{FLEET_END}"
    )


def configure_mode(mode: str, fleet_enabled: bool = False) -> None:
    config = ETC / "config.alloy"
    if not config.exists():
        return
    contents = config.read_text(encoding="utf-8")
    traces = "    traces = [otelcol.exporter.otlphttp.cloud.input]"
    disabled_traces = "    traces = []"
    if mode == "sdk":
        if traces in contents:
            contents = contents.replace(traces, disabled_traces, 1)
        elif disabled_traces not in contents:
            raise ValueError("cannot safely select SDK mode in the owned Alloy config")
    elif disabled_traces in contents:
        raise ValueError("switching an existing SDK-mode config back to Beyla-only is unsupported")

    begin_count = contents.count(FLEET_BEGIN)
    end_count = contents.count(FLEET_END)
    if begin_count != end_count or begin_count > 1:
        raise ValueError("cannot safely update Fleet configuration in the owned Alloy config")
    if begin_count:
        start = contents.index(FLEET_BEGIN)
        end = contents.index(FLEET_END, start) + len(FLEET_END)
        contents = contents[:start].rstrip() + contents[end:]
    if fleet_enabled:
        contents = contents.rstrip() + "\n\n" + fleet_block() + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".config-", dir=config.parent)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, config)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main() -> None:
    mode = required("BEYLA_SDK_MODE")
    if mode not in {"beyla-only", "sdk"}:
        raise ValueError("mode must be beyla-only or sdk")

    state_mode = STATE / "mode"
    initial_config = not state_mode.exists()
    if not initial_config:
        installed_mode = state_mode.read_text(encoding="utf-8").strip()
        if installed_mode != mode:
            raise ValueError("changing instrumentation mode after install is unsupported")
        if not (ETC / "alloy.env").exists() or not (ETC / "config.alloy").exists():
            raise ValueError("existing Alloy configuration is incomplete; refusing to recreate it")

    fleet_raw = os.environ.get("BEYLA_FLEET_ENABLED", "false").strip().lower()
    if fleet_raw not in {"true", "false", "yes", "no", "1", "0"}:
        raise ValueError("Fleet enabled must be true or false")
    fleet_enabled = fleet_raw in {"true", "yes", "1"}

    required_values = {
        "BEYLA_SDK_MODE": mode,
        "GRAFANA_CLOUD_OTLP_ENDPOINT": required("GRAFANA_CLOUD_OTLP_ENDPOINT"),
        "GRAFANA_CLOUD_OTLP_TENANT_ID": required("GRAFANA_CLOUD_OTLP_TENANT_ID"),
        "GRAFANA_CLOUD_OTLP_TOKEN": required("GRAFANA_CLOUD_OTLP_TOKEN"),
        "GRAFANA_CLOUD_METRICS_ENDPOINT": required("GRAFANA_CLOUD_METRICS_ENDPOINT"),
        "GRAFANA_CLOUD_METRICS_TENANT_ID": required("GRAFANA_CLOUD_METRICS_TENANT_ID"),
        "GRAFANA_CLOUD_METRICS_TOKEN": required("GRAFANA_CLOUD_METRICS_TOKEN"),
        "GRAFANA_CLOUD_PROFILES_ENDPOINT": required("GRAFANA_CLOUD_PROFILES_ENDPOINT"),
        "GRAFANA_CLOUD_PROFILES_TENANT_ID": required("GRAFANA_CLOUD_PROFILES_TENANT_ID"),
        "GRAFANA_CLOUD_PROFILES_TOKEN": required("GRAFANA_CLOUD_PROFILES_TOKEN"),
        "BEYLA_OPEN_PORTS": required("BEYLA_OPEN_PORTS"),
    }
    if fleet_enabled and initial_config:
        required_values["GRAFANA_CLOUD_FLEET_URL"] = required("GRAFANA_CLOUD_FLEET_URL")
        required_values["GRAFANA_CLOUD_FLEET_INSTANCE_ID"] = required(
            "GRAFANA_CLOUD_FLEET_INSTANCE_ID"
        )

    services = []
    raw_services = os.environ.get("BEYLA_SDK_SERVICES", "")
    if mode == "sdk":
        services = [name.strip() for name in raw_services.split(",") if name.strip()]
        if not services or len(set(services)) != len(services):
            raise ValueError("SDK mode requires a unique list of controlled systemd services")
        for unit in services:
            if not UNIT_NAME.fullmatch(unit):
                raise ValueError(f"invalid systemd service unit name: {unit}")
            if not (ROOT / "etc/systemd/system" / unit).exists() and not any(
                (ROOT / base / unit).exists()
                for base in ("lib/systemd/system", "usr/lib/systemd/system")
            ):
                raise ValueError(f"selected systemd service does not exist: {unit}")
            dropin = DROPINS / f"{unit}.d/90-beyla.conf"
            expected = (
                "[Service]\n"
                "# beyla managed\n"
                f"EnvironmentFile={ETC / 'sdk.env'}\n"
                f"Environment=OTEL_INJECTOR_SERVICE_NAME={unit[:-len('.service')]}\n"
            )
            if dropin.exists() and dropin.read_text(encoding="utf-8") != expected:
                raise ValueError(f"refusing to overwrite modified service drop-in: {dropin}")
    elif raw_services.strip():
        raise ValueError("beyla-only mode cannot select SDK services")

    alloy_env = "\n".join(
        f"{key}={systemd_value(value)}" for key, value in required_values.items()
    ) + "\nCONFIG_FILE=" + systemd_value(str(ETC / "config.alloy")) + "\n"
    sdk_env = "\n".join(
        [
            "OTEL_EXPORTER_OTLP_ENDPOINT=" + systemd_value("http://127.0.0.1:14318"),
            "OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf",
            "OTEL_TRACES_EXPORTER=otlp",
            "OTEL_METRICS_EXPORTER=otlp",
            "OTEL_LOGS_EXPORTER=none",
            "OTEL_INJECTOR_CONFIG_FILE=" + systemd_value(
                "/opt/beyla/sdk/dist/injector/otelinject.conf"
            ),
            "LD_PRELOAD=" + systemd_value("/opt/beyla/sdk/dist/injector/libotelinject.so"),
        ]
    ) + "\n"

    # Validate all selected targets before writing any state to avoid partial
    # enrollment when a later unit collides.
    if initial_config:
        configure_mode(mode, fleet_enabled=fleet_enabled)
    if not (ETC / "alloy.env").exists():
        atomic_secret(ETC / "alloy.env", alloy_env)
    if mode == "sdk":
        if not (ETC / "sdk.env").exists():
            atomic_secret(ETC / "sdk.env", sdk_env)
        enrolled = []
        for unit in services:
            dropin = DROPINS / f"{unit}.d/90-beyla.conf"
            dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            contents = (
                "[Service]\n"
                "# beyla managed\n"
                f"EnvironmentFile={ETC / 'sdk.env'}\n"
                f"Environment=OTEL_INJECTOR_SERVICE_NAME={unit[:-len('.service')]}\n"
            )
            if not dropin.exists():
                dropin.write_text(contents, encoding="utf-8")
            dropin.chmod(0o644)
            enrolled.append(unit)
        (STATE / "services").parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        (STATE / "services").write_text("\n".join(enrolled) + "\n", encoding="utf-8")
    else:
        (STATE / "services").unlink(missing_ok=True)
    (STATE / "mode").parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    (STATE / "mode").write_text(mode + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
