#!/bin/sh

set -e  # Exit immediately if any command fails

# Default MOUNT_PATH if not set
MOUNT_PATH="${MOUNT_PATH:-/__otel_sdk_auto_instrumentation__}"

echo "Starting instrumentation population..."

# Check if instrumentation directory already has files
if [ -d "${MOUNT_PATH}" ] && [ -n "$(ls -A ${MOUNT_PATH} 2>/dev/null)" ]; then
  echo "Instrumentation directory ${MOUNT_PATH} already populated, skipping copy"
  exit 0
fi

# Create versioned directory
mkdir -p "${MOUNT_PATH}/dist"

# Copy instrumentation files
cp -r /dist/* "${MOUNT_PATH}/dist/"

echo "Successfully populated instrumentation files to ${MOUNT_PATH}"
