"use strict";

const semver = require("semver");
const fs = require("fs");
const path = require("path");

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
  return Object.keys(require.cache).some(key =>
    key.includes("@opentelemetry/sdk-node/build/src/sdk.js"),
  );
}

function getRequireArgsFromExecArgv() {
  const required = [];
  const args = process.execArgv;
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === "--require" || args[i] === "-r") && i + 1 < args.length) {
      required.push(args[++i]);
    } else if (args[i].startsWith("--require=")) {
      required.push(args[i].slice("--require=".length));
    } else if (args[i].startsWith("-r=")) {
      required.push(args[i].slice("-r=".length));
    }
  }

  return required;
}

function findNearestPackageJson(startDir) {
  let dir = startDir;
  while (true) {
    console.error(dir);
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function moduleHasOtelSdkPackageDependency(modulePath) {
  try {
    const appDir = process.argv[1] ? path.dirname(process.argv[1]) : process.cwd();
    const resolved = require.resolve(modulePath, { paths: [appDir, process.cwd()] });
    console.error(resolved);
    const pkgJsonPath = findNearestPackageJson(path.dirname(resolved));
    if (!pkgJsonPath) return false;
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
    const allDeps = { ...pkg.dependencies, ...pkg.peerDependencies };
    console.error(allDeps);
    return ("@opentelemetry/sdk-node" in allDeps) || ("@opentelemetry/auto-instrumentations-node" in allDeps);
  } catch (e) {
    return false;
  }
}

function moduleHasOtelSdkDependency(modulePath) {
  try {
    const appDir = process.argv[1] ? path.dirname(process.argv[1]) : process.cwd();
    const resolved = require.resolve(modulePath, { paths: [appDir, process.cwd()] });
    let dir = path.dirname(resolved);
    while (true) {
      const node_modules = path.join(dir, "node_modules");
      if (fs.existsSync(node_modules)) {
        const candidate = path.join(dir, "node_modules", "@opentelemetry", "sdk-node");
        return (fs.existsSync(candidate));
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return false;
  } catch (e) {
    return false;
  }
}

function isOtelSdkRequiredViaArgs() {
  return getRequireArgsFromExecArgv().some(m => moduleHasOtelSdkDependency(m) || moduleHasOtelSdkPackageDependency(m));
}

function findOtelSdkInNodeModules() {
  // process.argv[1] is the app entry script even when loaded via --require
  const startDir = process.argv[1] ? path.dirname(process.argv[1]) : process.cwd();
  let dir = startDir;

  while (true) {
    const candidate = path.join(dir, "node_modules", "@opentelemetry", "sdk-node");
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break; // reached filesystem root
    dir = parent;
  }
  return null;
}

function isOtelSdkInstalled() {
  return findOtelSdkInNodeModules() !== null;
}

function init() {
  try {
    if (isOtelSdkAlreadyLoaded() || isOtelSdkRequiredViaArgs()) {
      logError(
        "Node.js application is already using OpenTelemetry auto-instrumentation. Skipping auto-instrumentation.",
      );
      return;
    }

    if (isOtelSdkInstalled()) {
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
