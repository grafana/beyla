WORKDIR ?= $(HOME)
ARCH ?= x86_64
KERNEL_VER ?= 6.10.6
KERNEL ?= kernels/$(ARCH)/vmlinuz-linux-$(KERNEL_VER)
TARBALL ?= /tmp/rootfs.tar
# do NOT put ROOT_IMG on a tmpfs backed fs
ROOT_IMG ?= $(WORKDIR)/rootfs.qcow2
ROOT_IMAGE_RAW ?= $(WORKDIR)/rootfs.raw
REPO_ROOT ?= ../..
TARGET_TEST ?= run-integration-test-vm
TEST_OUTPUT = $(REPO_ROOT)/testoutput
MNT ?= mnt
IMG_SIZE ?= 20G
QEMU_BIN = qemu-system-$(ARCH)
QEMU := $(shell which $(QEMU_BIN))

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
	DOCKER_BUILDKIT=1 docker build -f Dockerfile --build-arg target=$(TARGET_TEST) --output "type=tar,dest=$(TARBALL)" .
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
	qemu-system-$(ARCH) -enable-kvm -cpu host -m 5120 -smp 8 -kernel $(KERNEL) -drive file=$(ROOT_IMG),format=qcow2 \
		-append "earlyprintk=ttyS0 console=ttyS0 root=/dev/sda rw quiet" \
		-virtfs local,path=$(REPO_ROOT),mount_tag=beyla,security_model=mapped,id=beyla \
		-virtfs local,path=$(TEST_OUTPUT),mount_tag=testout,security_model=mapped,id=testout \
		-net user,hostfwd=tcp::2222-:22 -net nic \
		-nographic

change-owner:
	@current_owner=$$(stat -c '%U' .); \
	chown -R $$current_owner $(TEST_OUTPUT)

clean:
	rm -f $(ROOT_IMG) $(ROOT_IMAGE_RAW) $(TARBALL)

