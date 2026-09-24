"use strict";

const fs = require("fs");
const path = require("path");
const { fileURLToPath } = require("url");

const maxPackageJsonBytes = 2 * 1024 * 1024;
const nodeExtensionFallbacks = [".js", ".json", ".node"];
const controlCharacter = /\p{Cc}/u;

// Detects service metadata from package metadata or a verified Node.js entrypoint.
function detectServiceMetadata(options = {}) {
  const cwd = path.resolve(options.cwd ?? process.cwd());
  const entryPoint = normalizeEntryPoint(
    options.entryPoint === undefined
      ? entryPointFromProcess(options.argv ?? process.argv, options.execArgv ?? process.execArgv)
      : options.entryPoint,
  );
  const env = options.env ?? process.env;
  const packageResult = findPackageMetadata(cwd, entryPoint, env);
  const packageName = parsePackageName(packageResult.metadata.name);
  const metadata = {
    name: "",
    namespace: "",
    version: cleanString(packageResult.metadata.version),
    nameSource: "",
    versionSource: packageResult.metadata.version ? "package.json" : "",
    warning: packageResult.warning,
  };

  if (packageName) {
    metadata.name = packageName.name;
    metadata.namespace = packageName.namespace;
    metadata.nameSource = "package.json";
    return metadata;
  }

  const entryPointName = serviceNameFromEntryPoint(cwd, entryPoint);
  if (entryPointName && nodeEntryPointExists(cwd, entryPoint)) {
    metadata.name = entryPointName;
    metadata.nameSource = "Node.js entrypoint";
  }
  return metadata;
}

// Finds the first applicable package manifest without crossing its boundary.
function findPackageMetadata(cwd, entryPoint, env) {
  const npmPackageJson = env.npm_package_json;
  if (npmPackageJson && !pathHasNodeModules(cwd, npmPackageJson)) {
    const result = readPackageJson(absolutePath(cwd, npmPackageJson));
    if (result.found) return result;
  }

  let directory = packageSearchStart(cwd, entryPoint);
  while (true) {
    const result = readPackageJson(path.join(directory, "package.json"));
    if (result.found) return result;
    const parent = path.dirname(directory);
    if (parent === directory) return emptyPackageResult();
    directory = parent;
  }
}

// Chooses the package lookup directory from the entrypoint or working directory.
function packageSearchStart(cwd, entryPoint) {
  if (!entryPoint || pathHasNodeModules(cwd, entryPoint)) return cwd;

  const resolvedFile = resolveNodeFile(cwd, entryPoint);
  if (resolvedFile) return path.dirname(resolvedFile);

  const resolved = absolutePath(cwd, entryPoint);
  const info = stat(resolved);
  if (info) return info.isDirectory() ? resolved : path.dirname(resolved);
  return path.dirname(resolved);
}

// Reads a bounded regular package manifest without following symbolic links.
function readPackageJson(filename) {
  let info;
  try {
    info = fs.lstatSync(filename);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "ENOTDIR") {
      return emptyPackageResult();
    }
    return unusablePackage(filename, error.message);
  }

  if (info.isSymbolicLink()) return unusablePackage(filename, "symbolic link");
  if (!info.isFile()) return unusablePackage(filename, "not a regular file");
  if (info.size > maxPackageJsonBytes) return unusablePackage(filename, "file exceeds 2 MiB");

  let descriptor;
  let contents;
  try {
    const noFollow = fs.constants.O_NOFOLLOW ?? 0;
    descriptor = fs.openSync(filename, fs.constants.O_RDONLY | noFollow);
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile()) return unusablePackage(filename, "not a regular file");
    if (opened.size > maxPackageJsonBytes) {
      return unusablePackage(filename, "file exceeds 2 MiB");
    }
    contents = fs.readFileSync(descriptor);
  } catch (error) {
    return unusablePackage(filename, error.message);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  if (contents.length > maxPackageJsonBytes) {
    return unusablePackage(filename, "file exceeds 2 MiB");
  }

  let value;
  try {
    value = JSON.parse(contents.toString("utf8"));
  } catch (error) {
    return unusablePackage(filename, error.message);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return unusablePackage(filename, "root value is not an object");
  }

  return {
    found: true,
    metadata: {
      valid: true,
      name: stringField(value.name),
      version: stringField(value.version),
      main: stringField(value.main),
    },
    warning: "",
  };
}

// Splits a valid package name into its service name and optional namespace.
function parsePackageName(value) {
  value = cleanString(value);
  if (!value || controlCharacter.test(value)) return null;
  if (!value.startsWith("@")) {
    return value.includes("/") ? null : { name: value, namespace: "" };
  }

  const separator = value.indexOf("/");
  const namespace = value.slice(1, separator);
  const name = value.slice(separator + 1);
  if (separator < 0 || !namespace || !name || name.includes("/")) return null;
  return { name, namespace };
}

// Derives a service-name candidate from a non-dependency entrypoint.
function serviceNameFromEntryPoint(cwd, entryPoint) {
  if (!entryPoint || pathHasNodeModules(cwd, entryPoint)) return "";
  const basename = path.basename(entryPoint);
  const name = cleanString(basename.slice(0, basename.length - path.extname(basename).length));
  if (!name || name === "." || name === ".." || name === "-" || controlCharacter.test(name)) {
    return "";
  }
  return name;
}

// Checks whether an entrypoint resolves using Node.js file and directory rules.
function nodeEntryPointExists(cwd, entryPoint) {
  if (resolveNodeFile(cwd, entryPoint)) return true;

  const directory = absolutePath(cwd, entryPoint);
  const info = stat(directory);
  if (!info || !info.isDirectory()) return false;

  const packageResult = readPackageJson(path.join(directory, "package.json"));
  if (packageResult.found && !packageResult.metadata.valid) return false;
  const main = packageResult.metadata.main;
  if (!main) return Boolean(resolveNodeExtensionFile(cwd, path.join(entryPoint, "index")));

  const mainEntry = path.isAbsolute(main) ? main : path.join(entryPoint, main);
  return Boolean(
    resolveNodeFile(cwd, mainEntry) ||
      resolveNodeExtensionFile(cwd, path.join(mainEntry, "index")) ||
      resolveNodeExtensionFile(cwd, path.join(entryPoint, "index")),
  );
}

// Resolves an exact Node.js file or one with a runtime extension fallback.
function resolveNodeFile(cwd, entryPoint) {
  return resolveRegularFile(cwd, entryPoint) || resolveNodeExtensionFile(cwd, entryPoint);
}

// Resolves a Node.js file by appending supported runtime extensions.
function resolveNodeExtensionFile(cwd, entryPoint) {
  for (const extension of nodeExtensionFallbacks) {
    const resolved = resolveRegularFile(cwd, `${entryPoint}${extension}`);
    if (resolved) return resolved;
  }
  return "";
}

// Resolves a path only when it identifies a regular file.
function resolveRegularFile(cwd, filename) {
  const resolved = absolutePath(cwd, filename);
  const info = stat(resolved);
  return info && info.isFile() ? resolved : "";
}

// Reports whether a path belongs to a node_modules directory.
function pathHasNodeModules(cwd, filename) {
  return absolutePath(cwd, normalizeEntryPoint(filename)).split(path.sep).includes("node_modules");
}

// Selects the application entrypoint from Node.js process arguments.
function entryPointFromProcess(argv, execArgv) {
  const entryUrl = optionValue(execArgv, "--entry-url");
  if (entryUrl) return normalizeEntryPoint(entryUrl);
  if (execArgv.some(isCodeLaunchOption)) return "";
  return argv[1] ?? "";
}

// Reads a separated or attached command-line option value.
function optionValue(args, option) {
  for (let index = 0; index < args.length; index++) {
    if (args[index] === option) return args[index + 1] ?? "";
    if (args[index].startsWith(`${option}=`)) return args[index].slice(option.length + 1);
  }
  return "";
}

// Identifies Node.js launch options that execute code without an entrypoint file.
function isCodeLaunchOption(value) {
  return (
    value === "-e" ||
    value === "-p" ||
    value === "-pe" ||
    value === "--eval" ||
    value.startsWith("--eval=") ||
    value === "--print" ||
    value.startsWith("--print=") ||
    value === "--interactive" ||
    value === "--run" ||
    value.startsWith("--run=")
  );
}

// Converts a file URL entrypoint to a filesystem path.
function normalizeEntryPoint(value) {
  if (typeof value !== "string" || !value) return "";
  if (!value.startsWith("file:")) return value;
  try {
    return fileURLToPath(value);
  } catch {
    return "";
  }
}

// Resolves a process path against its working directory.
function absolutePath(cwd, filename) {
  return path.isAbsolute(filename) ? path.normalize(filename) : path.resolve(cwd, filename);
}

// Returns file information without propagating lookup failures.
function stat(filename) {
  try {
    return fs.statSync(filename);
  } catch {
    return null;
  }
}

// Creates a package boundary result for an unsafe or unreadable manifest.
function unusablePackage(filename, reason) {
  return {
    found: true,
    metadata: emptyPackageMetadata(),
    warning: `could not read package metadata from ${filename}: ${reason}`,
  };
}

// Creates a result representing an absent package manifest.
function emptyPackageResult() {
  return { found: false, metadata: emptyPackageMetadata(), warning: "" };
}

// Creates empty package metadata for a missing or invalid manifest.
function emptyPackageMetadata() {
  return { valid: false, name: "", version: "", main: "" };
}

// Returns a JSON field only when it is a string.
function stringField(value) {
  return typeof value === "string" ? value : "";
}

// Trims a string value or returns an empty string for other types.
function cleanString(value) {
  return typeof value === "string" ? value.trim() : "";
}

module.exports = {
  detectServiceMetadata,
  entryPointFromProcess,
  maxPackageJsonBytes,
  parsePackageName,
  readPackageJson,
};
