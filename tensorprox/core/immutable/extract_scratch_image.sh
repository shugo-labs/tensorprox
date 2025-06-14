#!/bin/bash

# Extract Docker image contents script
# Usage: ./extract_docker_image.sh <image_tag> <ssh_user>

set -e  # Exit on error

# Check if required arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: $0 <image_tag> <ssh_user>"
    echo "Example: $0 my-image:latest ubuntu"
    exit 1
fi

SCRATCH_TAG="$1"
SSH_USER="$2"
EXTRACT_DIR="/home/${SSH_USER}/tensorprox/tensorprox/core/immutable"

echo "Pulling Docker image: ${SCRATCH_TAG}"
/usr/bin/docker pull "${SCRATCH_TAG}"

echo "Saving Docker image to tar file..."
/usr/bin/docker save "${SCRATCH_TAG}" -o /tmp/scratch_image.tar

echo "Extracting image tar file..."
tar -xf /tmp/scratch_image.tar -C /tmp

echo "Processing image blobs..."
for blob in /tmp/blobs/sha256/*; do
    # Check if file exists and is a valid tar archive before extracting
    if [ -f "$blob" ] && tar -tf "$blob" >/dev/null 2>&1; then
        echo "Extracting blob: $(basename "$blob")"
        tar -xf "$blob" -C "${EXTRACT_DIR}" 2>/dev/null || true
    fi
done

echo "Cleaning up temporary files..."
rm -f /tmp/scratch_image.tar
rm -rf /tmp/blobs /tmp/manifest.json /tmp/repositories

echo "Docker image extraction complete!"
echo "Files extracted to: ${EXTRACT_DIR}"