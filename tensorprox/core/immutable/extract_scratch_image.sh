#!/bin/bash

# Extract Docker image contents script
# Usage: ./extract_docker_image.sh <image_tag> <ssh_user>

# Make script executable (in case it wasn't set during transfer)
chmod +x "$0" 2>/dev/null || true

# Clean up existing Docker images first
echo "Cleaning up existing Docker images..."
IMAGE_IDS=$(docker images -aq)
if [ -n "$IMAGE_IDS" ]; then
    docker rmi -f $IMAGE_IDS || true
    echo "Removed existing Docker images"
else
    echo "No existing Docker images to remove"
fi

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
docker pull "${SCRATCH_TAG}"

echo "Saving Docker image to tar file..."
docker save "${SCRATCH_TAG}" -o /tmp/scratch_image.tar

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