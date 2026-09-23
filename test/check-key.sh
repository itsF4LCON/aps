set -uo pipefail

BASE_URL="${BASE_URL:-https://api.xivlabs.tech}"


KEY="${1:-${API_KEY:-}}"
if [ -z "$KEY" ]; then
  read -rp "Paste your API key (aps_...): " KEY
fi

if [ -z "$KEY" ]; then
  echo "No key given. Exiting."
  exit 1
fi

echo "Testing key against $BASE_URL ..."
echo

body=$(curl -s -o /tmp/aps_key_body -w "%{http_code}" \
  -X POST "$BASE_URL/scan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"url":"https://github.com"}')

echo "HTTP status: $body"
echo "Response:    $(cat /tmp/aps_key_body)"
echo

case "$body" in
  200)
    echo "SUCCESS — your key works. The API accepted it and returned a verdict."
    ;;
  401)
    echo "REJECTED — the API returned 401 Unauthorized."
    echo "   The key is invalid, was mistyped, or has been deactivated."
    ;;
  429)
    echo "RATE LIMITED — the key is valid, but you've hit the request limit."
    echo "   Wait 60 seconds and try again."
    ;;
  000)
    echo "COULD NOT CONNECT — no response from $BASE_URL."
    echo "   Check the URL, your internet, or whether the Worker is deployed."
    ;;
  *)
    echo "Unexpected status $body — see the response body above."
    ;;
esac

rm -f /tmp/aps_key_body
