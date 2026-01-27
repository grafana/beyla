#!/bin/sh

set -e  # Exit immediately if any command fails

# Validate if SDK_PKG_VERSION is set
if [ -z "${SDK_PKG_VERSION}" ]; then
  echo "ERROR: SDK_PKG_VERSION environment variable is not set"
  exit 1
fi

# Validate if MOUNT_PATH is set
if [ -z "${MOUNT_PATH}" ]; then
  echo "ERROR: MOUNT_PATH environment variable is not set"
  exit 1
fi

echo "Starting instrumentation population for SDK version ${SDK_PKG_VERSION}..."

TARGET_DIR="${MOUNT_PATH}/${SDK_PKG_VERSION}"

# Check if instrumentation directory already has files
if [ -d "${TARGET_DIR}" ] && [ -n "$(ls -A ${TARGET_DIR} 2>/dev/null)" ]; then
  echo "Instrumentation directory ${TARGET_DIR} already populated, skipping copy"
  exit 0
fi

# Create versioned directory
mkdir -p "${TARGET_DIR}"

# Copy instrumentation files
cp -r /dist/* "${TARGET_DIR}/"

echo "Successfully populated instrumentation files to ${TARGET_DIR}"
