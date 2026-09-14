#!/bin/sh

# guess OS_TYPE if not provided
OS_TYPE=${OS_TYPE:-}
if [ -z "$OS_TYPE" ]; then
  case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
    cygwin_nt*|mingw*|msys_nt*)
      OS_TYPE="windows"
      ;;
    linux*)
      if [ "$(ldd /bin/ls | grep -m1 'musl')" ]; then
        OS_TYPE="linux-musl"
      else
        OS_TYPE="linux-glibc"
      fi
      ;;
    darwin*)
      OS_TYPE="macos"
      ;;
  esac
fi

# guess OS architecture if not provided
ARCHITECTURE=${ARCHITECTURE:-}
if [ -z "$ARCHITECTURE" ]; then
  case $(uname -m) in
    x86_64)        ARCHITECTURE="x64" ;;
    aarch64|arm64) ARCHITECTURE="arm64" ;;
  esac
fi

# validate architecture
case "$ARCHITECTURE" in
  "x64"|"arm64")
    ;;
  *)
    echo "Set the architecture type using the ARCHITECTURE environment variable. Supported values: x64, arm64." >&2
    return 2
    ;;
esac

# validate input
case "$OS_TYPE" in
  "linux-glibc")
    DOTNET_RUNTIME_ID="linux-$ARCHITECTURE"
    ;;
  "linux-musl")
    DOTNET_RUNTIME_ID="linux-musl-$ARCHITECTURE"
    ;;
  "macos")
    DOTNET_RUNTIME_ID="osx-$ARCHITECTURE"
    ;;
  "windows")
    ;;
  *)
    echo "Set the operating system type using the OS_TYPE environment variable. Supported values: linux-glibc, linux-musl, macos, windows." >&2
    return 2
    ;;
esac

ENABLE_PROFILING=${ENABLE_PROFILING:-true}
case "$ENABLE_PROFILING" in
  "true"|"false")
    ;;
  *)
    echo "Invalid ENABLE_PROFILING. Supported values: true, false." >&2
    return 2
    ;;
esac

# set defaults
test -z "$OTEL_DOTNET_AUTO_HOME" && OTEL_DOTNET_AUTO_HOME="$HOME/.otel-dotnet-auto"


# check $OTEL_DOTNET_AUTO_HOME and change it to an absolute path
if [ -z "$(ls -A $OTEL_DOTNET_AUTO_HOME)" ]; then
  echo "There are no files under the location specified via OTEL_DOTNET_AUTO_HOME."
  return 1
fi
# get absulute path
if [ "$OS_TYPE" = "macos" ]; then
  OTEL_DOTNET_AUTO_HOME=$(greadlink -fn $OTEL_DOTNET_AUTO_HOME)
else
  OTEL_DOTNET_AUTO_HOME=$(readlink -fn $OTEL_DOTNET_AUTO_HOME)
fi
if [ -z "$OTEL_DOTNET_AUTO_HOME" ]; then
  echo "Failed to get OTEL_DOTNET_AUTO_HOME absolute path."
  return 1
fi
# on Windows change to Windows path format
if [ "$OS_TYPE" = "windows" ]; then
  OTEL_DOTNET_AUTO_HOME=$(cygpath -w $OTEL_DOTNET_AUTO_HOME)
fi
if [ -z "$OTEL_DOTNET_AUTO_HOME" ]; then
  echo "Failed to get OTEL_DOTNET_AUTO_HOME absolute Windows path."
  return 1
fi

# set the platform-specific path separator (; on Windows and : on others)
if [ "$OS_TYPE" = "windows" ]; then
  SEPARATOR=";"
else
  SEPARATOR=":"
fi

# Configure OpenTelemetry .NET Automatic Instrumentation
export OTEL_DOTNET_AUTO_HOME

# Configure .NET Core Runtime
DOTNET_STARTUP_HOOKS=${DOTNET_STARTUP_HOOKS:-}
if [ -z "$DOTNET_STARTUP_HOOKS" ]; then
  export DOTNET_STARTUP_HOOKS="${OTEL_DOTNET_AUTO_HOME}/net/OpenTelemetry.AutoInstrumentation.StartupHook.dll"
else
  export DOTNET_STARTUP_HOOKS="${OTEL_DOTNET_AUTO_HOME}/net/OpenTelemetry.AutoInstrumentation.StartupHook.dll${SEPARATOR}${DOTNET_STARTUP_HOOKS}"
fi

# Configure .NET CLR Profiler
if [ "$ENABLE_PROFILING" = "true" ]; then
  # Set the .NET CLR Profiler file sufix
  case "$OS_TYPE" in
    "linux-glibc"|"linux-musl")
      SUFIX="so"
      ;;
    "macos")
      SUFIX="dylib"
      ;;
    "windows")
      SUFIX="dll"
      ;;
    *)
      echo "BUG: Invalid OS_TYPE. Submit an issue in https://github.com/open-telemetry/opentelemetry-dotnet-instrumentation." >&2
      return 1
      ;;
  esac

  # Enable .NET Framework Profiling API
  if [ "$OS_TYPE" = "windows" ]
  then
    export COR_ENABLE_PROFILING="1"
    export COR_PROFILER="{918728DD-259F-4A6A-AC2B-B85E1B658318}"
    # Set paths for both bitness on Windows, see https://docs.microsoft.com/en-us/dotnet/core/run-time-config/debugging-profiling#profiler-location
    export COR_PROFILER_PATH_64="$OTEL_DOTNET_AUTO_HOME/win-x64/OpenTelemetry.AutoInstrumentation.Native.$SUFIX"
    export COR_PROFILER_PATH_32="$OTEL_DOTNET_AUTO_HOME/win-x86/OpenTelemetry.AutoInstrumentation.Native.$SUFIX"
  fi

  # Enable .NET Core Profiling API
  export CORECLR_ENABLE_PROFILING="1"
  export CORECLR_PROFILER="{918728DD-259F-4A6A-AC2B-B85E1B658318}"
  if [ "$OS_TYPE" = "windows" ]
  then
    # Set paths for both bitness on Windows, see https://docs.microsoft.com/en-us/dotnet/core/run-time-config/debugging-profiling#profiler-location
    export CORECLR_PROFILER_PATH_64="$OTEL_DOTNET_AUTO_HOME/win-x64/OpenTelemetry.AutoInstrumentation.Native.$SUFIX"
    export CORECLR_PROFILER_PATH_32="$OTEL_DOTNET_AUTO_HOME/win-x86/OpenTelemetry.AutoInstrumentation.Native.$SUFIX"
  else
    export CORECLR_PROFILER_PATH="$OTEL_DOTNET_AUTO_HOME/$DOTNET_RUNTIME_ID/OpenTelemetry.AutoInstrumentation.Native.$SUFIX"
  fi
fi

exec "$@"
