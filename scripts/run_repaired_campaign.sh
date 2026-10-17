#!/usr/bin/env bash
# Serial campaign with live measurement pilots and separately curated evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${IMAGE:-lantern-sdn-ids}"
PILOT="${1:-results/campaigns/measurement-pilot-20261012-v3}"
CAMPAIGN="${2:-results/campaigns/submission-20261012-measurement-v3}"
DESTINATION="${3:-submission-repaired-20261012}"
if [[ ! -f "$PILOT/manifest.json" ]]; then
    python3 -m experiments.campaign create --campaign "$PILOT" --thresholds-from submission
fi
python3 -m experiments.campaign pilot --campaign "$PILOT"
docker run --rm --network none -v "$PWD:/opt/lantern" --entrypoint python3 "$IMAGE" \
    -m experiments.analyze --raw "$PILOT" --output "$PILOT/tables"
if [[ ! -f "$CAMPAIGN/manifest.json" ]]; then
    python3 -m experiments.campaign create --campaign "$CAMPAIGN" --thresholds-from submission
fi
python3 -m experiments.campaign evaluate --campaign "$CAMPAIGN"
docker run --rm --network none -v "$PWD:/opt/lantern" --entrypoint python3 "$IMAGE" \
    -m experiments.package curate --campaign "$CAMPAIGN" --submission "$DESTINATION"
docker run --rm --network none -v "$PWD:/opt/lantern" --entrypoint python3 "$IMAGE" \
    -m experiments.report --submission "$DESTINATION" --output "$DESTINATION-results.md"
python3 -m replay export --submission "$DESTINATION" --output "output/lantern-repaired-20261012-replay.zip"
