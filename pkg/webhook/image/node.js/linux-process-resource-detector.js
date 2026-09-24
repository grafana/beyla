"use strict";

const { detectServiceMetadata } = require("./service-metadata");
const log = require("./log");

const serviceName = "service.name";
const serviceNamespace = "service.namespace";
const serviceVersion = "service.version";
const serviceKeys = [serviceName, serviceNamespace, serviceVersion];

class LinuxProcessResourceDetector {
  // Creates a detector with optional test or integration dependencies.
  constructor(options = {}) {
    this.environmentDetector = options.environmentDetector;
    this.resolveMetadata = options.resolveMetadata ?? detectServiceMetadata;
    this.logger = options.logger ?? log;
  }

  // Detects missing service attributes without interrupting SDK startup.
  detect() {
    let configured = {};
    try {
      configured = this.configuredServiceAttributes();
      const missingName = isMissingServiceName(configured[serviceName]);
      this.logNameState(configured[serviceName], missingName);
      if (!missingName && configured[serviceVersion]) return { attributes: configured };

      const metadata = this.resolveMetadata();
      if (metadata.warning) this.logger.warning(metadata.warning);
      return { attributes: mergeServiceMetadata(configured, metadata, missingName, this.logger) };
    } catch (error) {
      this.logger.warning(`service metadata detection failed: ${error.message}`);
      this.logger.debug(error.stack || String(error));
      return { attributes: configured };
    }
  }

  // Reads configured service attributes through the OpenTelemetry environment detector.
  configuredServiceAttributes() {
    const detector = this.environmentDetector ?? require("@opentelemetry/resources").envDetector;
    const attributes = detector.detect().attributes ?? {};
    return Object.fromEntries(
      serviceKeys.filter(key => attributes[key] !== undefined).map(key => [key, attributes[key]]),
    );
  }

  // Logs whether local service-name detection is required.
  logNameState(name, missing) {
    if (missing) {
      this.logger.info(
        "service.name was not found by OpenTelemetry resource detectors; " +
          "looking at Node.js application metadata",
      );
    } else {
      this.logger.info(`service.name was provided by OpenTelemetry resource detectors: ${name}; keeping it`);
    }
  }
}

// Adds locally detected values only where configured service attributes are missing.
function mergeServiceMetadata(configured, metadata, missingName, logger) {
  const attributes = { ...configured };
  if (missingName && metadata.name) {
    attributes[serviceName] = metadata.name;
    logger.info(`service.name detected from ${metadata.nameSource}: ${metadata.name}`);
    if (!attributes[serviceNamespace] && metadata.namespace) {
      attributes[serviceNamespace] = metadata.namespace;
      logger.info(`service.namespace detected from package.json scope: ${metadata.namespace}`);
    }
  } else if (missingName) {
    logger.info("service.name was not found in Node.js application metadata; keeping the SDK default");
  }

  if (!attributes[serviceVersion] && metadata.version) {
    attributes[serviceVersion] = metadata.version;
    logger.info(`service.version detected from ${metadata.versionSource}: ${metadata.version}`);
  }
  return attributes;
}

// Treats absent and SDK-generated service names as unresolved.
function isMissingServiceName(value) {
  return !value || value === "unknown_service" || String(value).startsWith("unknown_service:");
}

const linuxProcessResourceDetector = new LinuxProcessResourceDetector();

module.exports = {
  LinuxProcessResourceDetector,
  isMissingServiceName,
  linuxProcessResourceDetector,
};
