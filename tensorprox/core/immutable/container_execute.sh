#!/bin/bash
# Container execution script with error handling

CONTAINER_NAME="$1"
CONTAINER_PASSWORD="$2"
MACHINE_NAME="$3"
DURATION="$4"
LABEL_HASHES="$5"
PLAYLIST="$6"
KING_IP="$7"

# Log parameters for debugging
echo "DEBUG: Starting container execution" >&2
echo "DEBUG: Container: $CONTAINER_NAME" >&2
echo "DEBUG: Machine: $MACHINE_NAME" >&2

# Decrypt and load container
echo "DEBUG: Decrypting container..." >&2
if ! echo "$CONTAINER_PASSWORD" | gpg --batch --yes --passphrase-fd 0 -d /home/valiops/containers/${CONTAINER_NAME}.tar.enc | docker load; then
    echo "ERROR: Failed to load container" >&2
    exit 1
fi

echo "DEBUG: Container loaded, starting challenge..." >&2

# Run challenge inside container - EXACTLY like original but in container
docker run --rm --name ${CONTAINER_NAME}_${MACHINE_NAME}_$$ \
    --network host \
    --privileged \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    -v /home/valiops/tensorprox/tensorprox/core/immutable/challenge.sh:/challenge.sh:ro \
    -v /home/valiops/tensorprox/tensorprox/core/immutable/traffic_generator.py:/traffic_generator.py:ro \
    ${CONTAINER_NAME}:latest \
    /bin/bash /challenge.sh "$MACHINE_NAME" "$DURATION" "$LABEL_HASHES" "$PLAYLIST" "$KING_IP" /traffic_generator.py

exit_code=$?
echo "DEBUG: Challenge completed with exit code: $exit_code" >&2

# Clean up
docker rmi ${CONTAINER_NAME}:latest 2>/dev/null || true

exit $exit_code
