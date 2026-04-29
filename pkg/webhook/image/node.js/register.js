"use strict";

const semver = require("semver");

const upstreamRegisterFile = "./otel-register";
const autoInstrumentationPackageJson =
  "./node_modules/@opentelemetry/auto-instrumentations-node/package.json";
const defaultSupportedVersionRange = "^18.19.0 || >=20.6.0";

function logError(message) {
  console.error(message);
}

function getSupportedVersionRange() {
  try {
    const packageJson = require(autoInstrumentationPackageJson);
    return packageJson.engines && packageJson.engines.node
      ? packageJson.engines.node
      : defaultSupportedVersionRange;
  } catch (e) {
    return defaultSupportedVersionRange;
  }
}

function isOtelSdkAlreadyLoaded() {
  return Object.keys(require.cache).some(key => {
    return key.includes(
      "@opentelemetry/sdk-node/build/src/sdk.js",
    );
  });
}

function init() {
  try {
    if (isOtelSdkAlreadyLoaded()) {
      logError(
        "Node.js application is already instrumented with OpenTelemetry. Skipping auto-instrumentation.",
      );
      return;
    }

    const nodeJsVersion = process.version;
    const supportedVersions = getSupportedVersionRange();

    if (
      !semver.satisfies(nodeJsVersion, supportedVersions, {
        includePrerelease: true,
      })
    ) {
      logError(
        `The OpenTelemetry auto-instrumentation distribution does not support Node.js version (${nodeJsVersion}). Supported versions ${supportedVersions}.`,
      );
      return;
    }

    require(upstreamRegisterFile);
  } catch (e) {
    const details = e && e.stack ? e.stack : e;
    logError(`Initialization failed: ${details}`);
  }
}

init();
