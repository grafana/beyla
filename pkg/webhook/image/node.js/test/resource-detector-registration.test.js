"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const { loadWithLinuxProcessDetector } = require("../resource-detector-registration");

// Records registration log messages for assertions.
function createLogger() {
  const messages = { debug: [], warning: [] };
  return {
    messages,
    // Records a debug message.
    debug(message) {
      messages.debug.push(message);
    },
    // Records a warning message.
    warning(message) {
      messages.warning.push(message);
    },
  };
}

test("detector is prepended while upstream registration loads", () => {
  const detector = { detect() {} };
  const upstream = { detect() {} };
  const original = () => [upstream];
  const utils = { getResourceDetectorsFromEnv: original };
  let observed;

  const result = loadWithLinuxProcessDetector(
    () => {
      observed = utils.getResourceDetectorsFromEnv();
      return "loaded";
    },
    { detector, logger: createLogger(), utils },
  );

  assert.equal(result, "loaded");
  assert.deepEqual(observed, [detector, upstream]);
  assert.equal(utils.getResourceDetectorsFromEnv, original);
});

test("detector remains active when upstream detectors are disabled", () => {
  const detector = { detect() {} };
  const utils = { getResourceDetectorsFromEnv: () => [] };
  let observed;

  loadWithLinuxProcessDetector(
    () => {
      observed = utils.getResourceDetectorsFromEnv();
    },
    { detector, logger: createLogger(), utils },
  );

  assert.deepEqual(observed, [detector]);
});

test("upstream loading continues when the registry cannot be patched", () => {
  const logger = createLogger();
  const utils = {};
  Object.defineProperty(utils, "getResourceDetectorsFromEnv", {
    value: () => [],
    writable: false,
  });
  let loaded = false;

  loadWithLinuxProcessDetector(
    () => {
      loaded = true;
    },
    { detector: {}, logger, utils },
  );

  assert.equal(loaded, true);
  assert.equal(logger.messages.warning.length, 1);
});

test("registry is restored when upstream loading throws", () => {
  const original = () => [];
  const utils = { getResourceDetectorsFromEnv: original };

  assert.throws(
    () =>
      loadWithLinuxProcessDetector(
        () => {
          throw new Error("load failed");
        },
        { detector: {}, logger: createLogger(), utils },
      ),
    /load failed/,
  );
  assert.equal(utils.getResourceDetectorsFromEnv, original);
});
