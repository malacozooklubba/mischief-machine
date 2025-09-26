#!/usr/bin/env bash

set -euo pipefail

# Basic configurable variables
REMOTE_HOST=""   # Required: remote host (e.g. pi@192.168.0.1)
REMOTE_DIR=""    # Required: target directory on device
PYTHON="python3"
SERVICE_NAME="hotspot.service"                   # optional: systemd service name to restart, e.g. hotspot-portal
DO_CLEAN="0"                                      # optional: when 1, wipe remote dir before upload if rsync missing

# Parse flags: allow overrides without editing the file
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) REMOTE_HOST="$2"; shift; shift;;
    --dir) REMOTE_DIR="$2"; shift; shift;;
    --python) PYTHON="$2"; shift; shift;;
    --service) SERVICE_NAME="$2"; shift; shift;;
    --clean) DO_CLEAN="1"; shift;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

# Validate required parameters
if [[ -z "$REMOTE_HOST" ]]; then
  echo "Error: --host parameter is required"
  echo "Usage: $0 --host <remote_host> --dir <remote_directory> [options]"
  echo "Example: $0 --host pi@192.168.0.1 --dir ~/mischief-machine"
  exit 1
fi

if [[ -z "$REMOTE_DIR" ]]; then
  echo "Error: --dir parameter is required"
  echo "Usage: $0 --host <remote_host> --dir <remote_directory> [options]"
  echo "Example: $0 --host pi@192.168.0.1 --dir ~/mischief-machine"
  exit 1
fi

echo "Deploying to $REMOTE_HOST:$REMOTE_DIR"

# Upload project (prefer rsync; fallback to tar over SSH)
if command -v rsync >/dev/null 2>&1; then
  echo "Using rsync to upload..."
  rsync -az --delete \
    --exclude "*.pyc" \
    --exclude "__pycache__/" \
    --exclude ".git/" \
    --exclude "venv/" \
    ./ "$REMOTE_HOST:$REMOTE_DIR/"
else
  echo "rsync not found. Falling back to tar over SSH..."
  if [[ "$DO_CLEAN" == "1" ]]; then
    ssh "$REMOTE_HOST" bash -lc "mkdir -p '$REMOTE_DIR' && rm -rf '$REMOTE_DIR'/*"
  else
    ssh "$REMOTE_HOST" bash -lc "mkdir -p '$REMOTE_DIR'"
  fi
  tar \
    --exclude=".git" \
    --exclude="venv" \
    --exclude="__pycache__" \
    --exclude="*.pyc" \
    -czf - . | ssh "$REMOTE_HOST" tar -xzf - -C "$REMOTE_DIR"
fi

# Remote provision: create venv, install deps
ssh "$REMOTE_HOST" bash -lc "\
  set -euo pipefail; \
  mkdir -p '$REMOTE_DIR'; \
  cd '$REMOTE_DIR'; \
  if [[ ! -d venv ]]; then $PYTHON -m venv venv; fi; \
  source venv/bin/activate; \
  pip install --upgrade pip; \
  if [[ -f requirements.txt ]]; then pip install -r requirements.txt; fi; \
"

# Deploy start_hotspot.sh to /usr/local/bin
echo "Deploying start_hotspot.sh to /usr/local/bin..."
ssh "$REMOTE_HOST" sudo cp "$REMOTE_DIR/start_hotspot.sh" /usr/local/bin/start_hotspot.sh
ssh "$REMOTE_HOST" sudo chmod +x /usr/local/bin/start_hotspot.sh

# Optional: restart systemd service
if [[ -n "$SERVICE_NAME" ]]; then
  echo "Restarting service: $SERVICE_NAME"
  ssh "$REMOTE_HOST" sudo systemctl restart "$SERVICE_NAME"
  ssh "$REMOTE_HOST" sudo systemctl status "$SERVICE_NAME" --no-pager | sed -n '1,40p'
else
  echo "No service specified. To run manually on remote:"
  cat <<EOF
ssh $REMOTE_HOST bash -lc 'cd $REMOTE_DIR && source venv/bin/activate && FLASK_APP=app.py flask run --host=0.0.0.0 --port=80'
EOF
fi

echo "Deploy complete."