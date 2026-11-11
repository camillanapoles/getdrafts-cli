#!/bin/bash
#
# MobSF Docker Installation Script for iOS-Pentesting-Skill
#
# Usage: ./scripts/install-mobsf-docker.sh [--port PORT] [--detach]
#

set -e

PORT="${PORT:-8000}"
DETACH="${DETACH:-true}"
CONTAINER_NAME="mobsf-ios-pentest"
IMAGE_NAME="opensecurity/mobile-security-framework-mobsf"

echo "🔧 Installing MobSF via Docker..."
echo "   Port: $PORT"
echo "   Container: $CONTAINER_NAME"
echo ""

if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first:"
    echo "   macOS: brew install --cask docker"
    echo "   Ubuntu: curl -fsSL https://get.docker.com | sh"
    exit 1
fi

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "⚠️  Container '$CONTAINER_NAME' already exists."
    read -p "   Remove and recreate? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "   Removing existing container..."
        docker rm -f "${CONTAINER_NAME}" > /dev/null 2>&1 || true
    else
        echo "   Using existing container."
        docker start "${CONTAINER_NAME}"
        echo "✅ MobSF container started on http://127.0.0.1:${PORT}"
        echo ""
        echo "   Web UI: http://127.0.0.1:${PORT}"
        echo "   API: http://127.0.0.1:${PORT}/api/v1"
        exit 0
    fi
fi

echo "📥 Pulling MobSF Docker image..."
docker pull "${IMAGE_NAME}"

echo "🚀 Starting MobSF container..."
# Bind to 127.0.0.1 by default — MobSF has no authentication, so exposing the
# container on 0.0.0.0 would let any host on the network upload binaries and
# read scan results. Override with Mobsf_HOST=0.0.0.0 only behind a reverse
# proxy that provides authentication.
MOBSF_HOST="${MOBSF_HOST:-127.0.0.1}"
DOCKER_FLAGS=(-p "${MOBSF_HOST}:${PORT}:8000" --name "${CONTAINER_NAME}")
if [[ "$DETACH" == "true" ]]; then
    DOCKER_FLAGS=(-d "${DOCKER_FLAGS[@]}")
else
    DOCKER_FLAGS=(-it "${DOCKER_FLAGS[@]}")
fi

docker run "${DOCKER_FLAGS[@]}" "${IMAGE_NAME}"

if [[ "$DETACH" == "true" ]]; then
    echo "⏳ Waiting for MobSF to start..."
    for _ in {1..30}; do
        if curl -s "http://127.0.0.1:${PORT}" > /dev/null 2>&1; then
            echo "✅ MobSF is running!"
            echo ""
            echo "   Web UI: http://127.0.0.1:${PORT}"
            echo "   API: http://127.0.0.1:${PORT}/api/v1"
            echo ""
            echo "   To stop: docker stop ${CONTAINER_NAME}"
            echo "   To start: docker start ${CONTAINER_NAME}"
            echo "   To remove: docker rm -f ${CONTAINER_NAME}"
            exit 0
        fi
        sleep 2
    done

    echo "⚠️  MobSF started but health check timed out."
    echo "   Check logs: docker logs ${CONTAINER_NAME}"
fi
