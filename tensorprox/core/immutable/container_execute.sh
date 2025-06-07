#!/bin/bash
# Container execution script for immutable folder
# Place at: /home/valiops/tensorprox/tensorprox/core/immutable/container_execute.sh

# Parameters (same pattern as challenge.sh)
CONTAINER_NAME="$1"
CONTAINER_PASSWORD="$2"
MACHINE_NAME="$3"
DURATION="$4"
LABEL_HASHES="$5"
PLAYLIST="$6"
KING_IP="$7"

# Decrypt and load container
echo "$CONTAINER_PASSWORD" | gpg --batch --yes --passphrase-fd 0 -d /home/valiops/containers/${CONTAINER_NAME}.tar.enc | docker load

# Run challenge inside container with miner's challenge.sh
docker run --rm --name ${CONTAINER_NAME}_${MACHINE_NAME}_$$ \
    --network host \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    -v /home/valiops/tensorprox/tensorprox/core/immutable/challenge.sh:/challenge.sh:ro \
    -v /home/valiops/tensorprox/tensorprox/core/immutable/traffic_generator.py:/traffic_generator.py:ro \
    -e MACHINE_NAME="$MACHINE_NAME" \
    -e DURATION="$DURATION" \
    -e LABEL_HASHES="$LABEL_HASHES" \
    -e PLAYLIST="$PLAYLIST" \
    -e KING_IP="$KING_IP" \
    ${CONTAINER_NAME}:latest \
    /bin/bash /challenge.sh "$MACHINE_NAME" "$DURATION" "$LABEL_HASHES" "$PLAYLIST" "$KING_IP" /traffic_generator.py

# Clean up
docker rmi ${CONTAINER_NAME}:latest