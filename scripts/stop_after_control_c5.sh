#!/usr/bin/env bash
set -u

CAMPAIGN_DIR="${1:-results/campaigns/native-extended-20-v6}"
EXECUTION="$CAMPAIGN_DIR/execution.jsonl"
TARGET_LABEL="control20-C5-none"

if [[ ! -f "$EXECUTION" ]]; then
  echo "Execution file not found: $EXECUTION" >&2
  exit 1
fi

PARENT_PID="${CAMPAIGN_PID:-}"
if [[ -z "$PARENT_PID" ]]; then
  PARENT_PID="$(pgrep -fo 'python3 -m experiments\.campaign extended --campaign results/campaigns/native-extended-20-v6' || true)"
fi

if [[ -z "$PARENT_PID" ]]; then
  echo "Campaign parent process not found; refusing to stop anything." >&2
  exit 1
fi

if ! kill -0 "$PARENT_PID" 2>/dev/null; then
  echo "Campaign parent PID $PARENT_PID is not running." >&2
  exit 1
fi

echo "Watching $EXECUTION"
echo "Will stop campaign PID $PARENT_PID after $TARGET_LABEL trial 20 is recorded."

while kill -0 "$PARENT_PID" 2>/dev/null; do
  if awk -v label="$TARGET_LABEL" '
    /"run"/ && $0 ~ "\\\"label\\\": \\\"" label "\\\"" && $0 ~ /\\\"trial\\\": 20/ && $0 ~ /\\\"exit_code\\\": 0/ { found=1 }
    END { exit(found ? 0 : 1) }
  ' "$EXECUTION"; then
    echo "Trial 20 recorded; stopping campaign before the next run."
    kill -INT "$PARENT_PID" 2>/dev/null || true
    sleep 2
    if kill -0 "$PARENT_PID" 2>/dev/null; then
      echo "Campaign did not exit after SIGINT; sending SIGTERM." >&2
      kill -TERM "$PARENT_PID" 2>/dev/null || true
    fi
    exit 0
  fi
  sleep 2
done

echo "Campaign parent exited before the boundary was reached." >&2
exit 2
