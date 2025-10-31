WORKDIR ?= $(HOME)
ARCH ?= x86_64
KERNEL_VER ?= 6.10.6
KERNEL ?= kernels/$(ARCH)/vmlinuz-linux-$(KERNEL_VER)
TARBALL ?= /tmp/rootfs.tar
# do NOT put ROOT_IMG on a tmpfs backed fs
ROOT_IMG ?= $(WORKDIR)/rootfs.qcow2
ROOT_IMAGE_RAW ?= $(WORKDIR)/rootfs.raw
REPO_ROOT ?= ../../..
TARGET_TEST ?= run-integration-test-vm
TEST_PATTERN ?= TestMultiProcess
RUN_NUMBER ?= 1
TEST_OUTPUT = $(REPO_ROOT)/testoutput
MNT ?= mnt
IMG_SIZE ?= 20G
QEMU_BIN = qemu-system-$(ARCH)
QEMU := $(shell which $(QEMU_BIN))
PRECOMPILED_TESTS_DIR ?= 
COMPILED_TEST_BINARY ?= compiled-integration-test

.PHONY: all clean launchvm change-owner check_qemu

all: launchvm change-owner

check_qemu:
ifeq ($(QEMU),)
	$(error "$(QEMU_BIN) binary not found. Cannot proceed.")
endif
	@echo "QEMU is available at $(QEMU)"

# Ensure test output directory exists
$(TEST_OUTPUT):
	mkdir -p $(TEST_OUTPUT)

$(ROOT_IMG): Dockerfile
	# Build the Docker image and create a tarball
	DOCKER_BUILDKIT=1 docker build --quiet -f Dockerfile \
		--build-arg target=$(TARGET_TEST) \
		--build-arg test_pattern=$(TEST_PATTERN) \
		--build-arg run_number=$(RUN_NUMBER) \
		--output "type=tar,dest=$(TARBALL)" .
	# Create a raw image, format it, and extract the tarball
	fallocate -l $(IMG_SIZE) $(ROOT_IMAGE_RAW)
	mkfs.ext4 $(ROOT_IMAGE_RAW)
	[ -d $(MNT) ] || mkdir -p $(MNT)
	sudo mount -o loop $(ROOT_IMAGE_RAW) mnt
	sudo tar -xf $(TARBALL) -C $(MNT)
	sync -f $(MNT) && sudo umount -l $(MNT)
	rm -f $(TARBALL) && rmdir $(MNT)
	# Convert the raw image to qcow2 format
	qemu-img convert $(ROOT_IMAGE_RAW) -O qcow2 $(ROOT_IMG) && rm $(ROOT_IMAGE_RAW)

# Size qeumu VM to match github runner, using 75% of the resources:
#   .75 * 16 cores = 12 cores
#   .75 * 64 GBRAM = 48
launchvm: check_qemu $(ROOT_IMG) $(TEST_OUTPUT)
	@PRECOMPILED_VIRTFS=""; \
	if [ -n "$(PRECOMPILED_TESTS_DIR)" ] && [ -d "$(PRECOMPILED_TESTS_DIR)" ]; then \
		echo "Starting QEMU with pre-compiled tests from $(PRECOMPILED_TESTS_DIR)"; \
		PRECOMPILED_VIRTFS="-virtfs local,path=$(PRECOMPILED_TESTS_DIR),mount_tag=precompiled,security_model=mapped,id=precompiled"; \
	fi; \
	qemu-system-$(ARCH) -enable-kvm -cpu host -m 49152 -smp 12 -kernel $(KERNEL) -drive file=$(ROOT_IMG),format=qcow2 \
		-append "earlyprintk=ttyS0 console=ttyS0 root=/dev/sda rw quiet" \
		-virtfs local,path=$(REPO_ROOT),mount_tag=beyla,security_model=mapped,id=beyla \
		-virtfs local,path=$(TEST_OUTPUT),mount_tag=testout,security_model=mapped,id=testout \
		$$PRECOMPILED_VIRTFS \
		-net user,hostfwd=tcp::2222-:22 -net nic \
		-nographic

change-owner:
	@current_owner=$$(stat -c '%U' .); \
	chown -R $$current_owner $(TEST_OUTPUT)

clean:
	rm -f $(ROOT_IMG) $(ROOT_IMAGE_RAW) $(TARBALL)

