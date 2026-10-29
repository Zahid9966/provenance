#!/bin/sh
set -e
# PROVENANCE_DEMO=1 seeds synthetic data + demo users on first start (works on SQLite and Postgres).
# Real deployments: omit it, then  docker exec -it <ctr> python -m provenance create-user <name> <role>
# and drop partner files into /data/landing.
if [ "$PROVENANCE_DEMO" = "1" ]; then python -m provenance init --if-empty; fi
exec python -m provenance serve --port 8787 --schedule-minutes "${PROVENANCE_SCHEDULE_MINUTES:-5}"
