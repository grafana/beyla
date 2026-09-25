"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { LinuxProcessResourceDetector } = require("../linux-process-resource-detector");

// Records detector log messages for assertions.
function createLogger() {
  const messages = { debug: [], info: [], warning: [] };
  return {
    messages,
    // Records a debug message.
    debug(message) {
      messages.debug.push(message);
    },
    // Records an informational message.
    info(message) {
      messages.info.push(message);
    },
    // Records a warning message.
    warning(message) {
      messages.warning.push(message);
    },
  };
}

// Creates an OpenTelemetry environment detector that returns fixed attributes.
function environmentDetector(attributes) {
  return { detect: () => ({ attributes }) };
}

test("package metadata fills missing service attributes", () => {
  const logger = createLogger();
  const detector = new LinuxProcessResourceDetector({
    environmentDetector: environmentDetector({}),
    logger,
    resolveMetadata: () => ({
      name: "orders",
      namespace: "acme",
      version: "1.2.3",
      nameSource: "package.json",
      versionSource: "package.json",
      warning: "",
    }),
  });

  const result = detector.detect();

  assert.deepEqual(result.attributes, {
    "service.name": "orders",
    "service.namespace": "acme",
    "service.version": "1.2.3",
  });
  assert.ok(logger.messages.info.some(message => message.includes("looking at Node.js")));
  assert.ok(logger.messages.info.some(message => message.includes("detected from package.json")));
});

test("configured service metadata takes precedence", () => {
  let resolverCalls = 0;
  const logger = createLogger();
  const detector = new LinuxProcessResourceDetector({
    environmentDetector: environmentDetector({
      "service.name": "configured",
      "service.namespace": "production",
      "service.version": "9",
      "other.attribute": "ignored",
    }),
    logger,
    resolveMetadata: () => {
      resolverCalls++;
      return {};
    },
  });

  const result = detector.detect();

  assert.deepEqual(result.attributes, {
    "service.name": "configured",
    "service.namespace": "production",
    "service.version": "9",
  });
  assert.equal(resolverCalls, 0);
  assert.ok(logger.messages.info.some(message => message.includes("configured; keeping it")));
});

test("package scope is not applied when a configured name wins", () => {
  const detector = new LinuxProcessResourceDetector({
    environmentDetector: environmentDetector({ "service.name": "configured" }),
    logger: createLogger(),
    resolveMetadata: () => ({
      name: "orders",
      namespace: "acme",
      version: "1.2.3",
      nameSource: "package.json",
      versionSource: "package.json",
      warning: "",
    }),
  });

  const result = detector.detect();

  assert.deepEqual(result.attributes, {
    "service.name": "configured",
    "service.version": "1.2.3",
  });
});

test("unknown service names are replaced while configured namespace is preserved", () => {
  const detector = new LinuxProcessResourceDetector({
    environmentDetector: environmentDetector({
      "service.name": "unknown_service:node",
      "service.namespace": "production",
    }),
    logger: createLogger(),
    resolveMetadata: () => ({
      name: "orders",
      namespace: "acme",
      version: "",
      nameSource: "Node.js entrypoint",
      versionSource: "",
      warning: "",
    }),
  });

  const result = detector.detect();

  assert.deepEqual(result.attributes, {
    "service.name": "orders",
    "service.namespace": "production",
  });
});

test("missing application metadata keeps the SDK default", () => {
  const logger = createLogger();
  const detector = new LinuxProcessResourceDetector({
    environmentDetector: environmentDetector({}),
    logger,
    resolveMetadata: () => ({ name: "", namespace: "", version: "", warning: "" }),
  });

  const result = detector.detect();

  assert.deepEqual(result.attributes, {});
  assert.ok(logger.messages.info.some(message => message.includes("keeping the SDK default")));
});

test("detection failures retain configured values and do not throw", () => {
  const logger = createLogger();
  const detector = new LinuxProcessResourceDetector({
    environmentDetector: environmentDetector({ "service.name": "configured" }),
    logger,
    resolveMetadata: () => {
      throw new Error("read failed");
    },
  });

  const result = detector.detect();

  assert.deepEqual(result.attributes, { "service.name": "configured" });
  assert.equal(logger.messages.warning.length, 1);
  assert.match(logger.messages.warning[0], /read failed/);
});

test("package boundary warnings do not discard fallback metadata", () => {
  const logger = createLogger();
  const detector = new LinuxProcessResourceDetector({
    environmentDetector: environmentDetector({}),
    logger,
    resolveMetadata: () => ({
      name: "main",
      namespace: "",
      version: "",
      nameSource: "Node.js entrypoint",
      versionSource: "",
      warning: "invalid package.json",
    }),
  });

  const result = detector.detect();

  assert.equal(result.attributes["service.name"], "main");
  assert.deepEqual(logger.messages.warning, ["invalid package.json"]);
});
