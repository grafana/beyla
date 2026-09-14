"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
const opentelemetry = require("@opentelemetry/sdk-node");
const api_1 = require("@opentelemetry/api");
const core_1 = require("@opentelemetry/core");
const utils_1 = require("./utils");
const logLevel = (0, core_1.getStringFromEnv)('OTEL_LOG_LEVEL');
if (logLevel != null) {
    api_1.diag.setLogger(new api_1.DiagConsoleLogger(), {
        logLevel: (0, core_1.diagLogLevelFromString)(logLevel),
    });
}
const sdk = new opentelemetry.NodeSDK({
    instrumentations: (0, utils_1.getNodeAutoInstrumentations)(),
    resourceDetectors: (0, utils_1.getResourceDetectorsFromEnv)(),
});
try {
    sdk.start();
    api_1.diag.info('OpenTelemetry automatic instrumentation started successfully');
}
catch (error) {
    api_1.diag.error('Error initializing OpenTelemetry SDK. Your application is not instrumented and will not produce telemetry', error);
}
async function shutdown() {
    try {
        await sdk.shutdown();
        api_1.diag.debug('OpenTelemetry SDK terminated');
    }
    catch (error) {
        api_1.diag.error('Error terminating OpenTelemetry SDK', error);
    }
}
// Gracefully shutdown SDK if a SIGTERM is received
process.on('SIGTERM', shutdown);
// Gracefully shutdown SDK if Node.js is exiting normally
process.once('beforeExit', shutdown);
//# sourceMappingURL=register.js.map