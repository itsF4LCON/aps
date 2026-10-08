#!/usr/bin/env bash
# Downloads the evaluation data into eval/data (git-ignored; neither list may
# be redistributed here). Usage: eval/fetch.sh [days of OpenPhish history] [Tranco size]
set -euo pipefail

DAYS="${1:-30}"
TOP="${2:-10000}"
OUT="$(dirname "$0")/data"
mkdir -p "$OUT"

# Phishing: every URL the OpenPhish community feed listed in the last $DAYS days.
# The feed is a git repo, so its history holds far more than the current 300.
if [ -d "$OUT/public_feed/.git" ]; then
  git -C "$OUT/public_feed" pull -q
else
  git clone -q https://github.com/openphish/public_feed.git "$OUT/public_feed"
fi
git -C "$OUT/public_feed" log --since="$DAYS days ago" --format= -p -- feed.txt \
  | grep -E '^\+https?://' | sed 's/^+//' | sort -u > "$OUT/phish.txt"
git -C "$OUT/public_feed" log -1 --format='%H %cs' > "$OUT/phish.version"

# Legitimate: the top $TOP domains of the Tranco list, as bare https:// URLs.
curl -sSf https://tranco-list.eu/top-1m-id > "$OUT/tranco.id"
curl -sSfL "https://tranco-list.eu/download/$(cat "$OUT/tranco.id")/$TOP" \
  | tr -d '\r' | cut -d, -f2 | sed 's|^|https://|; s|$|/|' > "$OUT/benign.txt"

wc -l "$OUT/phish.txt" "$OUT/benign.txt"
echo "OpenPhish $(cat "$OUT/phish.version"), Tranco list $(cat "$OUT/tranco.id")"
