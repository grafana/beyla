WORKDIR ?= $(HOME)
HOST_ARCH ?= x86_64
TARGET_ARCH ?= x86_64
KERNEL_VER ?= 6.10.6
TARBALL ?= /tmp/rootfs.tar
# do NOT put ROOT_IMG on a tmpfs backed fs
ROOT_IMG ?= $(WORKDIR)/rootfs.qcow2
ROOT_IMAGE_RAW ?= $(WORKDIR)/rootfs.raw
REPO_ROOT ?= ../..
TARGET_TEST ?= run-integration-test-vm
TEST_OUTPUT = $(REPO_ROOT)/testoutput
MNT ?= mnt
IMG_SIZE ?= 20G

.PHONY: all clean launchvm change-owner check_qemu

QEMU_TARGET_ARCH=$(TARGET_ARCH)
QEMU_HOST_ARCH=$(HOST_ARCH)

ifeq ($(TARGET_ARCH),arm64)
	QEMU_TARGET_ARCH=aarch64
endif

ifeq ($(HOST_ARCH),arm64)
	QEMU_HOST_ARCH=aarch64
endif

QEMU_BIN = qemu-system-$(QEMU_TARGET_ARCH)
QEMU := $(shell which $(QEMU_BIN))

ifeq ($(QEMU_HOST_ARCH),x86_64)
	ifeq ($(QEMU_TARGET_ARCH),aarch64)
		QEMU_CPU_FLAGS=-cpu max
	endif

	ifeq ($(QEMU_TARGET_ARCH),x86_64)
		QEMU_CPU_FLAGS=-cpu host -enable-kvm
	endif
endif

ifeq ($(QEMU_HOST_ARCH),aarch64)
	ifeq ($(QEMU_TARGET_ARCH),aarch64)
		QEMU_CPU_FLAGS=-cpu host
	endif

	ifeq ($(QEMU_TARGET_ARCH),x86_64)
		QEMU_CPU_FLAGS=-cpu max
	endif
endif

ifeq ($(QEMU_TARGET_ARCH),aarch64)
	QEMU_MACHINE_TYPE=-M type=virt,accel=tcg,highmem=on
	QEMU_KERNEL_CMDLINE=earlyprintk=ttyAMA0 console=ttyAMA0 root=/dev/vda rw quiet
else
	QEMU_KERNEL_CMDLINE=earlyprintk=ttyS0 console=ttyS0 root=/dev/sda rw quiet
endif

KERNEL ?= kernels/$(QEMU_TARGET_ARCH)/vmlinuz-linux-$(KERNEL_VER)

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
	DOCKER_BUILDKIT=1 docker build --platform linux/$(QEMU_TARGET_ARCH) -f Dockerfile --build-arg target=$(TARGET_TEST) --output "type=tar,dest=$(TARBALL)" .
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

launchvm: check_qemu $(ROOT_IMG) $(TEST_OUTPUT)
	$(QEMU) $(QEMU_MACHINE_TYPE) $(QEMU_CPU_FLAGS) -m 5120 -smp 8 \
		-kernel $(KERNEL) \
		-drive file=$(ROOT_IMG),format=qcow2 \
		-append "$(QEMU_KERNEL_CMDLINE)" \
		-virtfs local,path=$(REPO_ROOT),mount_tag=beyla,security_model=mapped,id=beyla \
		-virtfs local,path=$(TEST_OUTPUT),mount_tag=testout,security_model=mapped,id=testout \
		-net user,hostfwd=tcp::2222-:22 -net nic \
		-nographic

change-owner:
	@current_owner=$$(stat -c '%U' .); \
	chown -R $$current_owner $(TEST_OUTPUT)

clean:
	rm -f $(ROOT_IMG) $(ROOT_IMAGE_RAW) $(TARBALL)

