#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
relative_log=${LANTERN_LOG#"$repo"/}
container_log=/opt/lantern/$relative_log
docker_bin=${DOCKER_BIN:-/mnt/c/Program\ Files/Docker/Docker/resources/bin/docker.exe}
repo_mount=$(wslpath -w "$repo")
controller_port=${LANTERN_CONTROLLER_PORT:-6653}

exec "$docker_bin" run --rm -p "$controller_port:$controller_port" \
  -v "$repo_mount:/opt/lantern" \
  -w /opt/lantern \
  -e PYTHONPATH=/opt/lantern \
  -e LANTERN_LOG="$container_log" \
  -e LANTERN_MITIGATOR="${LANTERN_MITIGATOR:-none}" \
  -e LANTERN_CASE="${LANTERN_CASE:-}" \
  -e LANTERN_TRIAL="${LANTERN_TRIAL:-0}" \
  -e LANTERN_DETECTOR_MODE="${LANTERN_DETECTOR_MODE:-both}" \
  -e LANTERN_POLICY="${LANTERN_POLICY:-class}" \
  -e LANTERN_CONTROLLER_IP="${LANTERN_CONTROLLER_IP:-0.0.0.0}" \
  -e LANTERN_CONTROLLER_PORT="$controller_port" \
  -e LANTERN_TOPOLOGY_SIZE="${LANTERN_TOPOLOGY_SIZE:-6}" \
  -e LANTERN_WINDOW_SECONDS="${LANTERN_WINDOW_SECONDS:-10.0}" \
  -e LANTERN_PROFILE_ALPHA="${LANTERN_PROFILE_ALPHA:-0.2}" \
  -e LANTERN_CUMULATIVE_LATERAL="${LANTERN_CUMULATIVE_LATERAL:-0}" \
  lantern-sdn-ids "$@"
