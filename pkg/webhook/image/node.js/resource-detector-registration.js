"use strict";

const { linuxProcessResourceDetector } = require("./linux-process-resource-detector");
const log = require("./log");

// Loads upstream registration with the Beyla detector prepended temporarily.
function loadWithLinuxProcessDetector(load, options = {}) {
  const detector = options.detector ?? linuxProcessResourceDetector;
  const logger = options.logger ?? log;
  let utils;
  try {
    // The upstream package changed its bundled utility filename from utils.js
    // to utils.cjs in v0.82. Keep patching the same module used by its register
    // entrypoint for both layouts.
    if (options.utils) {
      utils = options.utils;
    } else {
      let utilsModule;
      try {
        utilsModule = require.resolve("./utils.cjs");
      } catch (error) {
        if (error.code !== "MODULE_NOT_FOUND") throw error;
        utilsModule = require.resolve("./utils");
      }
      utils = require(utilsModule);
    }
  } catch (error) {
    logger.warning(`could not load the OpenTelemetry resource detector registry: ${error.message}`);
    return load();
  }

  const original = utils.getResourceDetectorsFromEnv;
  if (typeof original !== "function") {
    logger.warning("OpenTelemetry resource detector registration is unavailable");
    return load();
  }

  try {
    // Prepends Beyla while preserving the configured upstream detector order.
    utils.getResourceDetectorsFromEnv = () => [detector, ...original.call(utils)];
  } catch (error) {
    logger.warning(`could not register the Node.js service metadata detector: ${error.message}`);
    return load();
  }

  try {
    return load();
  } finally {
    try {
      utils.getResourceDetectorsFromEnv = original;
    } catch (error) {
      logger.debug(`could not restore the OpenTelemetry resource detector registry: ${error.message}`);
    }
  }
}

module.exports = { loadWithLinuxProcessDetector };
