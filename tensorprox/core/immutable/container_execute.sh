#!/bin/bash
# Container execution script with complete internal logging and error handling

CONTAINER_NAME="$1"
CONTAINER_PASSWORD="$2"
MACHINE_NAME="$3"
DURATION="$4"
LABEL_HASHES="$5"
PLAYLIST="$6"
KING_IP="$7"

# Internal logging function
log_debug() {
    echo "DEBUG: $1" >&2
}

log_error() {
    echo "ERROR: $1" >&2
}

# Log all parameters for debugging
log_debug "Starting container execution"
log_debug "Container: $CONTAINER_NAME"
log_debug "Machine: $MACHINE_NAME"
log_debug "Duration: $DURATION"
log_debug "King IP: $KING_IP"

# Internal check: Verify container file exists
CONTAINER_FILE="/home/valiops/containers/${CONTAINER_NAME}.tar.enc"
if [ ! -f "$CONTAINER_FILE" ]; then
    log_error "Container file not found: $CONTAINER_FILE"
    exit 1
fi

# Internal check: Get container file size and basic info
CONTAINER_SIZE=$(stat -f%z "$CONTAINER_FILE" 2>/dev/null || stat -c%s "$CONTAINER_FILE" 2>/dev/null || echo "unknown")
log_debug "Container file size: $CONTAINER_SIZE bytes"

# Internal check: Test Docker availability
if ! command -v docker >/dev/null 2>&1; then
    log_error "Docker not available"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    log_error "Docker daemon not running"
    exit 1
fi

log_debug "Docker is available and running"

# Decrypt and load container with internal error checking
log_debug "Decrypting container..."
if ! echo "$CONTAINER_PASSWORD" | gpg --batch --yes --passphrase-fd 0 -d "$CONTAINER_FILE" | docker load; then
    log_error "Failed to decrypt and load container"
    log_error "Check if container password is correct"
    exit 1
fi

log_debug "Container loaded successfully"

# Internal check: Verify image was loaded
if ! docker images | grep -q "$CONTAINER_NAME"; then
    log_error "Container image not found after loading"
    exit 1
fi

log_debug "Container image verified in Docker"

# Internal check: Verify required files exist in container context
CHALLENGE_SCRIPT="/home/valiops/tensorprox/tensorprox/core/immutable/challenge.sh"
TRAFFIC_GENERATOR="/home/valiops/tensorprox/tensorprox/core/immutable/traffic_generator.py"

if [ ! -f "$CHALLENGE_SCRIPT" ]; then
    log_error "Challenge script not found: $CHALLENGE_SCRIPT"
    exit 1
fi

if [ ! -f "$TRAFFIC_GENERATOR" ]; then
    log_error "Traffic generator not found: $TRAFFIC_GENERATOR"
    exit 1
fi

log_debug "Required scripts verified"
log_debug "Starting challenge inside container..."

# Run challenge inside container with comprehensive logging
CONTAINER_ID="${CONTAINER_NAME}_${MACHINE_NAME}_$$"
docker run --rm --name "$CONTAINER_ID" \
    --network host \
    --privileged \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    -v "$CHALLENGE_SCRIPT:/challenge.sh:ro" \
    -v "$TRAFFIC_GENERATOR:/traffic_generator.py:ro" \
    "${CONTAINER_NAME}:latest" \
    /bin/bash /challenge.sh "$MACHINE_NAME" "$DURATION" "$LABEL_HASHES" "$PLAYLIST" "$KING_IP" /traffic_generator.py

challenge_exit_code=$?
log_debug "Challenge completed with exit code: $challenge_exit_code"

# Internal cleanup with logging
log_debug "Cleaning up container image..."
if docker rmi "${CONTAINER_NAME}:latest" >/dev/null 2>&1; then
    log_debug "Container image removed successfully"
else
    log_debug "Container image cleanup failed or already removed"
fi

# Internal verification: Ensure cleanup completed
REMAINING_IMAGES=$(docker images | grep -c "$CONTAINER_NAME" || echo "0")
if [ "$REMAINING_IMAGES" -eq 0 ]; then
    log_debug "Cleanup verified - no container images remaining"
else
    log_debug "Warning: $REMAINING_IMAGES container images still present"
fi

log_debug "Container execution completed"
exit $challenge_exit_code