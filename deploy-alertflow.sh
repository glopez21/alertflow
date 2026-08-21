#!/usr/bin/env bash
# deploy-alertflow.sh — Deploy AlertFlow stack to clu5t3r
#
# Usage:
#   ./deploy-alertflow.sh          # full deploy (copy + build + start)
#   ./deploy-alertflow.sh --pull   # rebuild only (no copy)
set -euo pipefail

REMOTE="clu5t3r"
REMOTE_DIR="/home/x5pyd3rx/alertflow"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== AlertFlow Deploy to $REMOTE ==="

# ── Step 1: Create remote directory ────────────────────────────
echo "[1/4] Ensuring remote directory exists..."
ssh "$REMOTE" "mkdir -p $REMOTE_DIR"

# ── Step 2: Copy project files ─────────────────────────────────
if [[ "${1:-}" != "--pull" ]]; then
    echo "[2/4] Copying project to $REMOTE:$REMOTE_DIR ..."
    rsync -avz --delete \
        --exclude '.venv' \
        --exclude '__pycache__' \
        --exclude '.git' \
        --exclude '*.pyc' \
        --exclude 'alertflow.db' \
        "$PROJECT_DIR/" "$REMOTE:$REMOTE_DIR/"
else
    echo "[2/4] Skipping copy (--pull mode)"
fi

# ── Step 3: Copy compose + env ─────────────────────────────────
echo "[3/4] Setting up compose files..."
ssh "$REMOTE" "cp $REMOTE_DIR/docker-compose.alertflow.yml $REMOTE_DIR/docker-compose.clu5t3r.yml"
ssh "$REMOTE" "if [ ! -f $REMOTE_DIR/.env ]; then cp $REMOTE_DIR/.env.alertflow $REMOTE_DIR/.env; fi"

# ── Step 4: Build and start ────────────────────────────────────
echo "[4/4] Building and starting containers..."
ssh "$REMOTE" "cd $REMOTE_DIR && docker compose -f docker-compose.clu5t3r.yml up -d --build"

echo ""
echo "=== Deploy complete ==="
echo "  AlertFlow API:  http://$REMOTE:8082/api/health"
echo "  Kafka broker:   localhost:19092 (from clu5t3r)"
echo ""
echo "To check status:  ssh $REMOTE 'cd $REMOTE_DIR && docker compose -f docker-compose.clu5t3r.yml ps'"
echo "To view logs:     ssh $REMOTE 'cd $REMOTE_DIR && docker compose -f docker-compose.clu5t3r.yml logs -f alertflow'"
