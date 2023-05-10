#!/bin/sh
docker buildx build --platform "darwin/arm64,darwin/amd64,linux/386,linux/amd64,linux/arm64,linux/arm/v7,windows/386,windows/amd64" --output "./dist" --target "artifact" .

