#!/bin/bash
# Hybrid container execution: challenge.sh on host, echo from container

CONTAINER_NAME="$1"
CONTAINER_PASSWORD="$2"
MACHINE_NAME="$3"
DURATION="$4"
LABEL_HASHES="$5"
PLAYLIST="$6"
KING_IP="$7"

# Log parameters for debugging
echo "DEBUG: Starting hybrid container execution" >&2
echo "DEBUG: Container: $CONTAINER_NAME" >&2
echo "DEBUG: Machine: $MACHINE_NAME" >&2

# Decrypt and load container
echo "DEBUG: Decrypting container..." >&2
if ! echo "$CONTAINER_PASSWORD" | gpg --batch --yes --passphrase-fd 0 -d /home/valiops/containers/${CONTAINER_NAME}.tar.enc | docker load; then
    echo "ERROR: Failed to load container" >&2
    exit 1
fi

echo "DEBUG: Container loaded, starting host-based challenge with container echo..." >&2

# Run challenge.sh on HOST but capture its output
CHALLENGE_SCRIPT="/home/valiops/tensorprox/tensorprox/core/immutable/challenge.sh"
TRAFFIC_GENERATOR="/home/valiops/tensorprox/tensorprox/core/immutable/traffic_generator.py"

# Capture challenge output in a variable
challenge_output=$(/bin/bash "$CHALLENGE_SCRIPT" "$MACHINE_NAME" "$DURATION" "$LABEL_HASHES" "$PLAYLIST" "$KING_IP" "$TRAFFIC_GENERATOR" 2>/dev/null)
challenge_exit_code=$?

echo "DEBUG: Challenge host execution completed with exit code: $challenge_exit_code" >&2

# If challenge succeeded, output the results using container's echo (trusted binary)
if [ $challenge_exit_code -eq 0 ] && [ -n "$challenge_output" ]; then
    echo "DEBUG: Outputting results via container echo..." >&2
    docker run --rm "${CONTAINER_NAME}:latest" echo "$challenge_output"
else
    echo "DEBUG: Challenge failed or no output generated" >&2
fi

# Clean up
docker rmi ${CONTAINER_NAME}:latest 2>/dev/null || true

exit $challenge_exit_code