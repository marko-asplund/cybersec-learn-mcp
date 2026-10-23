#!/usr/bin/env bash
# MCP 2025-11-25: initialize -> initialized -> tools/resources/prompts discovery.
set -euo pipefail

MCP_URL="${MCP_URL:-http://127.0.0.1:8000/mcp}"
PROTOCOL_VERSION="2025-11-25"
REQUEST_ID=1
WORK_DIR="$(mktemp -d)"
HEADERS="$WORK_DIR/headers"
BODY="$WORK_DIR/body"
trap 'rm -rf "$WORK_DIR"' EXIT

for cmd in curl jq; do
  command -v "$cmd" >/dev/null || { echo "Missing dependency: $cmd" >&2; exit 1; }
done

# Format either a JSON response or JSON messages embedded in an SSE response.
response_json() {
  if grep -qi '^content-type:.*text/event-stream' "$HEADERS"; then
    # MCP SSE sends each JSON-RPC message in a 'data:' field.
    sed -n 's/^data:[[:space:]]*//p' "$BODY"
  else
    cat "$BODY"
  fi
}

print_response() {
  if [[ ! -s "$BODY" ]]; then
    echo '(no response body)'
  elif grep -qi '^content-type:.*text/event-stream' "$HEADERS"; then
    # Display each SSE JSON-RPC message with jq; ignore non-data SSE fields.
    response_json | while IFS= read -r line; do
      jq . <<<"$line" || printf '%s\n' "$line"
    done
  else
    jq . "$BODY" || cat "$BODY"
  fi
}

post_json() {
  local payload="$1"
  shift
  local status
  status="$(curl -sS --max-time 30 -D "$HEADERS" -o "$BODY" -w '%{http_code}' \
    -X POST "$MCP_URL" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    "$@" --data-binary "$payload")"
  printf 'HTTP %s\n' "$status"
  print_response
  if [[ ! "$status" =~ ^2[0-9][0-9]$ ]]; then
    echo "Request failed with HTTP $status" >&2
    exit 1
  fi
}

# Phase 1: Initialize — negotiate version/capabilities and obtain session ID.
echo '=== 1. initialize ==='
INIT_JSON="$(jq -nc --arg v "$PROTOCOL_VERSION" '{
  jsonrpc:"2.0", id:1, method:"initialize",
  params:{protocolVersion:$v, capabilities:{}, clientInfo:{name:"curl-discovery-legacy", version:"1.0"}}
}')"
# Intentionally omit MCP-Protocol-Version on initialize (legacy SDK routing).
post_json "$INIT_JSON"

SESSION_ID="$(awk 'tolower($1)=="mcp-session-id:" {gsub("\r","",$2); print $2}' "$HEADERS" | tail -n 1)"
NEGOTIATED_VERSION="$(response_json | jq -r 'select(.id == 1) | .result.protocolVersion // empty' | head -n 1)"
if [[ -z "$NEGOTIATED_VERSION" ]]; then
  echo 'Initialization response did not contain a negotiated protocol version.' >&2
  exit 1
fi
PROTOCOL_VERSION="$NEGOTIATED_VERSION"
echo "Protocol: $PROTOCOL_VERSION"
echo "Session ID: ${SESSION_ID:-<not issued; stateless legacy transport>}"

COMMON_HEADERS=(-H "MCP-Protocol-Version: $PROTOCOL_VERSION")
if [[ -n "$SESSION_ID" ]]; then
  COMMON_HEADERS+=(-H "Mcp-Session-Id: $SESSION_ID")
fi

# Phase 2: Send initialized notification — no JSON-RPC result is expected.
echo
echo '=== 2. notifications/initialized ==='
post_json '{"jsonrpc":"2.0","method":"notifications/initialized"}' "${COMMON_HEADERS[@]}"

legacy_list() {
  local method="$1"
  REQUEST_ID=$((REQUEST_ID + 1))
  local payload
  payload="$(jq -nc --arg method "$method" --argjson id "$REQUEST_ID" \
    '{jsonrpc:"2.0", id:$id, method:$method, params:{}}')"
  echo
  echo "=== $method ==="
  post_json "$payload" "${COMMON_HEADERS[@]}"
}

# Phase 3: Discover tools and their input schemas.
legacy_list 'tools/list'

# Phase 4: Discover concrete resources and URI templates.
legacy_list 'resources/list'
legacy_list 'resources/templates/list'

# Phase 5: Discover prompts and their arguments.
legacy_list 'prompts/list'

# Phase 6: Close legacy session if server issued an ID.
if [[ -n "$SESSION_ID" ]]; then
  echo
  echo '=== 6. DELETE session (optional cleanup) ==='
  status="$(curl -sS --max-time 15 -D "$HEADERS" -o "$BODY" -w '%{http_code}' \
    -X DELETE "$MCP_URL" "${COMMON_HEADERS[@]}")"
  echo "HTTP $status"
  print_response
else
  echo
  echo '=== 6. No session ID to close ==='
fi

