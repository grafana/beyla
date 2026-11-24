#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int nvmlInit_v2(void) {
  return (getenv("BEYLA_NVML_FAIL_INIT") &&
          getenv("BEYLA_NVML_FAIL_INIT")[0] == '1')
             ? 999
             : 0;
}
int nvmlShutdown(void) { return 0; }
const char *nvmlErrorString(int code) { return "fixture error"; }
int nvmlDeviceGetCount_v2(unsigned *count) {
  *count = 1;
  return 0;
}
int nvmlDeviceGetHandleByIndex_v2(unsigned index, void **handle) {
  *handle = (void *)1;
  return 0;
}
int nvmlDeviceGetName(void *handle, char *name, unsigned size) {
  snprintf(name, size, "Fixture GPU");
  return 0;
}
int nvmlDeviceGetUUID(void *handle, char *uuid, unsigned size) {
  snprintf(uuid, size, "GPU-fixture");
  return 0;
}
int nvmlDeviceGetUtilizationRates(void *handle, unsigned *rates) {
  rates[0] = 42;
  rates[1] = 17;
  return 0;
}
int nvmlDeviceGetMemoryInfo(void *handle, uint64_t *memory) {
  memory[0] = 4096;
  memory[1] = 3072;
  memory[2] = 1024;
  return 0;
}
int nvmlDeviceGetPowerUsage(void *handle, unsigned *value) {
  *value = 125000;
  return 0;
}
/* An available symbol can still report an unsupported reading. */
int nvmlDeviceGetFanSpeed(void *handle, unsigned *value) { return 3; }
