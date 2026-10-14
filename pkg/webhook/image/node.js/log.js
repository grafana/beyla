"use strict";

const prefix = "[Beyla OpenTelemetry Injector Node.js]";

// Writes an informational injector message.
function info(message) {
  console.error(`${prefix} ${message}`);
}

// Writes a non-fatal injector warning.
function warning(message) {
  console.error(`${prefix} ${message}`);
}

// Writes diagnostic details when injector debug logging is enabled.
function debug(message) {
  if (process.env.OTEL_INJECTOR_LOG_LEVEL === "debug") {
    console.error(`${prefix} ${message}`);
  }
}

module.exports = { debug, info, warning };
