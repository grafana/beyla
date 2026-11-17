# Keep `make <task>` working while Mise owns the task definitions.
# Each goal is forwarded separately: GNU make serializes goals by default, and
# callers can opt into parallel independent goals with `make -j`.
.DEFAULT_GOAL := __mise

.PHONY: __mise $(MAKECMDGOALS)

ifneq ($(strip $(MAKECMDGOALS)),)
$(MAKECMDGOALS):
	$(if $(filter run-integration-test-vm,$@),bash .mise/tasks/integration/run/vm,mise run $@)
endif

__mise:
	$(if $(filter run-integration-test-vm,$(MAKECMDGOALS)),bash .mise/tasks/integration/run/vm,mise run all)
